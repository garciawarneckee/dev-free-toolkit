#!/usr/bin/env python3
"""Consulta la base pública OSV (osv.dev) por vulnerabilidades conocidas.

Sirve cuando no hay escáner instalado: solo usa la librería estándar y no
ejecuta nada del proyecto. Cubre únicamente las dependencias que se le pasan
(normalmente las directas), no las transitivas.

Uso:
    python3 osv_consulta.py Maven org.apache.logging.log4j:log4j-core 2.14.1 Maven com.h2database:h2 1.4.197
    python3 osv_consulta.py --archivo deps.txt   # una "ecosistema nombre versión" por línea
    python3 osv_consulta.py --detalle ...        # lista completa en vez del resumen por paquete

Por defecto resume por paquete (conteo por severidad y detalle solo de críticas y
altas) para no llenar el contexto con cientos de avisos repetidos.

Ecosistemas válidos: Maven, npm, PyPI, Go, RubyGems, Packagist, NuGet, crates.io
"""
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

API = "https://api.osv.dev/v1"
ORDEN = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def _curl(*args):
    # curl usa los certificados del sistema; urllib falla en el Python de python.org para macOS.
    r = subprocess.run(["curl", "-sSf", "--max-time", "30", *args], capture_output=True, text=True, check=True)
    return json.loads(r.stdout)


def _post(url, cuerpo):
    return _curl("-X", "POST", "-H", "Content-Type: application/json", "-d", json.dumps(cuerpo), url)


def _get(url):
    return _curl(url)


def _versiones_arregladas(vuln, nombre):
    arregladas = set()
    for afectado in vuln.get("affected", []):
        if afectado.get("package", {}).get("name") != nombre:
            continue
        for rango in afectado.get("ranges", []):
            for evento in rango.get("events", []):
                if "fixed" in evento:
                    arregladas.add(evento["fixed"])
    return sorted(arregladas)


def consultar(deps):
    consultas = [{"package": {"ecosystem": e, "name": n}, "version": v} for e, n, v in deps]
    resultados = _post(f"{API}/querybatch", {"queries": consultas})["results"]
    ids = {ref["id"] for res in resultados for ref in res.get("vulns", [])}
    with ThreadPoolExecutor(max_workers=16) as pool:
        detalles = dict(zip(ids, pool.map(lambda i: _get(f"{API}/vulns/{i}"), ids)))
    salida = []
    for (eco, nombre, version), res in zip(deps, resultados):
        for ref in res.get("vulns", []):
            vuln = detalles[ref["id"]]
            salida.append({
                "paquete": nombre,
                "version": version,
                "id": vuln["id"],
                "alias": [a for a in vuln.get("aliases", []) if a.startswith("CVE-")],
                "severidad": vuln.get("database_specific", {}).get("severity", "DESCONOCIDA"),
                "resumen": vuln.get("summary", ""),
                "arreglada_en": _versiones_arregladas(vuln, nombre),
            })
    salida.sort(key=lambda x: (ORDEN.get(x["severidad"], 9), x["paquete"]))
    return salida


def resumir(vulns):
    paquetes = {}
    for v in vulns:
        p = paquetes.setdefault((v["paquete"], v["version"]), {
            "paquete": v["paquete"], "version": v["version"], "conteo": {}, "criticas_y_altas": []})
        p["conteo"][v["severidad"]] = p["conteo"].get(v["severidad"], 0) + 1
        if v["severidad"] in ("CRITICAL", "HIGH"):
            p["criticas_y_altas"].append({k: v[k] for k in ("severidad", "id", "alias", "resumen", "arreglada_en")})
    return list(paquetes.values())


def _leer_args(argv):
    if argv[:1] == ["--archivo"]:
        with open(argv[1]) as f:
            argv = f.read().split()
    if not argv or len(argv) % 3:
        sys.exit(__doc__)
    return [tuple(argv[i:i + 3]) for i in range(0, len(argv), 3)]


if __name__ == "__main__":
    args = sys.argv[1:]
    detalle = "--detalle" in args
    deps = _leer_args([a for a in args if a != "--detalle"])
    vulns = consultar(deps)
    clave, valor = ("vulnerabilidades", vulns) if detalle else ("paquetes_vulnerables", resumir(vulns))
    print(json.dumps({"dependencias_consultadas": len(deps), clave: valor}, indent=1, ensure_ascii=False))
