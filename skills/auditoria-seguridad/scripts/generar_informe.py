#!/usr/bin/env python3
"""Genera los dos entregables de la auditoría a partir de un único JSON.

    python3 generar_informe.py auditoria-seguridad.json [--salida DIR]

Escribe en DIR (por defecto, la carpeta del JSON):
  - AUDITORIA-SEGURIDAD.html  para el dueño del negocio: riesgos e impacto, sin jerga.
  - AUDITORIA-SEGURIDAD.md    para quien lo arregle: hallazgos técnicos con archivo y línea.

También completa el JSON de entrada: calcula "totals" y, si "repo.path" es un
repositorio git, agrega "repo.commit". El formato está documentado en el SKILL.md.
Si el JSON tiene errores, el script los lista todos juntos y termina con código 1,
sin escribir nada.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
VERSION = 1

STATUS = {
    "red": ("e-critico", "Riesgo alto"),
    "yellow": ("e-atencion", "Riesgo moderado"),
    "green": ("e-bien", "Riesgo bajo"),
}
URGENCY = {
    "now": ("e-critico", "Arreglar ya", "Arreglar ya"),
    "soon": ("e-serio", "En las próximas semanas", "Próximas semanas"),
    "later": ("e-atencion", "Cuando puedas", "Más adelante"),
}
ACTOR = {
    "insider": "Alguien de tu equipo",
    "user": "Un usuario registrado",
    "anyone": "Cualquiera en internet",
}
RISK_SEVERITY = {"high": "Grave", "medium": "Seria", "low": "Menor"}
IMPACTS = {
    "data": ("🔓", "Robo o filtración de datos"),
    "money": ("💸", "Pérdida de dinero"),
    "legal": ("⚖️", "Problemas legales o multas"),
    "reputation": ("📉", "Daño a tu reputación"),
    "outage": ("⛔", "La app deja de funcionar"),
    "takeover": ("🕹️", "Alguien toma el control"),
}
EFFORT = {"hours": "Unas horas", "days": "Algunos días", "weeks": "Varias semanas"}
FINDING_SEVERITY = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
CONFIDENCE = {"confirmed": "Confirmado", "suspected": "A verificar"}
CATEGORY = {
    "sqli": "SQL Injection",
    "xss": "XSS",
    "csrf": "CSRF",
    "cors": "CORS",
    "authn": "Autenticación",
    "authz": "Autorización",
    "secrets": "Secretos",
    "dependencies": "Dependencias",
    "config": "Configuración",
}


def validate(d):
    err = []

    def req(obj, key, where, kind=str):
        if not isinstance(obj.get(key), kind) or (kind in (str, list) and not obj.get(key)):
            err.append(f"{where}: falta '{key}' ({kind.__name__} no vacío)")

    def enum(obj, key, options, where):
        if obj.get(key) not in options:
            err.append(f"{where}: '{key}' = {obj.get(key)!r}; opciones: {', '.join(options)}")

    def str_list(obj, key, where):
        if not isinstance(obj.get(key, []), list) or not all(isinstance(x, str) for x in obj.get(key, [])):
            err.append(f"{where}: '{key}' debe ser una lista de textos")

    if d.get("version") != VERSION:
        err.append(f"raíz: 'version' debe ser {VERSION}")
    for k in ("project", "date", "verdict", "purpose"):
        req(d, k, "raíz")
    enum(d, "status", STATUS, "raíz")
    for k in ("risks", "findings"):
        if not isinstance(d.get(k), list):
            err.append(f"raíz: '{k}' debe ser una lista")
    for k in ("stack", "assets", "strengths", "limitations"):
        str_list(d, k, "raíz")
    if "repo" in d and not isinstance(d["repo"], dict):
        err.append("raíz: 'repo' debe ser un objeto {path, commit}")
    if "tools" in d:
        if not isinstance(d["tools"], dict):
            err.append("raíz: 'tools' debe ser un objeto {used, missing}")
        else:
            str_list(d["tools"], "used", "tools")
            str_list(d["tools"], "missing", "tools")

    finding_ids = {f.get("id") for f in d.get("findings", []) if isinstance(f, dict)}
    for i, r in enumerate(d.get("risks", [])):
        where = f"risks[{i}] ({r.get('id', '?')})"
        for k in ("id", "title", "scenario"):
            req(r, k, where)
        req(r, "affects", where, list)
        req(r, "impacts", where, list)
        for imp in r.get("impacts", []):
            if imp not in IMPACTS:
                err.append(f"{where}: impact {imp!r} inválido; opciones: {', '.join(IMPACTS)}")
        enum(r, "actor", ACTOR, where)
        enum(r, "severity", RISK_SEVERITY, where)
        enum(r, "urgency", URGENCY, where)
        enum(r, "effort", EFFORT, where)
        for fid in r.get("findings", []):
            if fid not in finding_ids:
                err.append(f"{where}: referencia al finding {fid!r}, que no existe")
    for i, f in enumerate(d.get("findings", [])):
        where = f"findings[{i}] ({f.get('id', '?')})"
        for k in ("id", "title", "cause", "fix"):
            req(f, k, where)
        req(f, "locations", where, list)
        enum(f, "severity", FINDING_SEVERITY, where)
        enum(f, "confidence", CONFIDENCE, where)
        enum(f, "category", CATEGORY, where)
    for i, p in enumerate((d.get("dependencies") or {}).get("packages", [])):
        enum(p, "severity", FINDING_SEVERITY, f"dependencies.packages[{i}] ({p.get('name', '?')})")
    return err


def complete(d):
    d["totals"] = {
        "risks": {u: sum(r["urgency"] == u for r in d["risks"]) for u in URGENCY},
        "findings": {s: sum(f["severity"] == s for f in d["findings"]) for s in FINDING_SEVERITY},
    }
    repo = d.get("repo") or {}
    if repo.get("path") and not repo.get("commit"):
        r = subprocess.run(["git", "-C", repo["path"], "rev-parse", "--short", "HEAD"], capture_output=True, text=True)
        if r.returncode == 0:
            repo["commit"] = r.stdout.strip()
    return d


def render_html(d):
    template = (BASE / "assets" / "plantilla.html").read_text(encoding="utf-8")
    data = json.dumps(d, ensure_ascii=False, indent=1).replace("<", "\\u003c")
    return template.replace("__DATOS__", data)


def render_md(d):
    order = list(FINDING_SEVERITY)
    findings = sorted(d["findings"], key=lambda f: order.index(f["severity"]))
    risk_of = {fid: r["id"] for r in d["risks"] for fid in r.get("findings", [])}
    repo = d.get("repo") or {}
    out = [f"# Auditoría de seguridad — {d['project']}",
           f"Fecha: {d['date']} · Semáforo: {STATUS[d['status']][1]}"
           + (f" · Commit: `{repo['commit']}`" if repo.get("commit") else ""), "",
           f"> {d['verdict']}", "",
           "Informe técnico para quien haga los arreglos. El resumen para el dueño está en AUDITORIA-SEGURIDAD.html.", ""]
    if d.get("stack"):
        out += [f"Stack: {', '.join(d['stack'])}", ""]
    out += ["## Hallazgos", "", "| # | Severidad | Categoría | Dónde | Riesgo |", "|---|---|---|---|---|"]
    for f in findings:
        sev = FINDING_SEVERITY[f["severity"]] + (" (a verificar)" if f["confidence"] == "suspected" else "")
        out.append(f"| {f['id']} | {sev} | {CATEGORY[f['category']]} | {', '.join(f'`{x}`' for x in f['locations'])} | {risk_of.get(f['id'], '—')} |")
    for f in findings:
        out += ["", f"### {f['id']} — {f['title']} ({FINDING_SEVERITY[f['severity']]}, {CONFIDENCE[f['confidence']].lower()})",
                f"- **Dónde:** {', '.join(f'`{x}`' for x in f['locations'])}",
                f"- **Causa:** {f['cause']}",
                f"- **Cómo se arregla:** {f['fix']}"]
    dep = d.get("dependencies")
    if dep:
        out += ["", "## Dependencias", f"Herramienta: {dep.get('tool', '—')}. {dep.get('summary', '')}"]
        if dep.get("packages"):
            out += ["", "| Paquete | Instalada | Severidad | Se arregla en |", "|---|---|---|---|"]
            out += [f"| {p.get('name', '')} | {p.get('version', '')} | {FINDING_SEVERITY.get(p.get('severity'), '')} | {p.get('fixed', '')} |"
                    for p in dep["packages"]]
    tools = d.get("tools") or {}
    if tools:
        out += ["", "## Herramientas", f"- Usadas: {', '.join(tools.get('used', [])) or '—'}",
                f"- No disponibles: {', '.join(tools.get('missing', [])) or '—'}"]
    out += ["", "## Lo que está bien"] + [f"- {x}" for x in d.get("strengths", [])]
    out += ["", "## Límites de esta auditoría"] + [f"- {x}" for x in d.get("limitations", [])]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("json")
    ap.add_argument("--salida")
    a = ap.parse_args()
    path = Path(a.json)
    try:
        d = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as ex:
        sys.exit(f"No se pudo leer {path}: {ex}")
    errors = validate(d)
    if errors:
        print("El JSON tiene errores; corregilos y volvé a correr:", *errors, sep="\n- ", file=sys.stderr)
        sys.exit(1)
    complete(d)
    out = Path(a.salida) if a.salida else path.parent
    out.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(d, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (out / "AUDITORIA-SEGURIDAD.html").write_text(render_html(d), encoding="utf-8")
    (out / "AUDITORIA-SEGURIDAD.md").write_text(render_md(d), encoding="utf-8")
    print(f"Listo:\n  {out / 'AUDITORIA-SEGURIDAD.html'}\n  {out / 'AUDITORIA-SEGURIDAD.md'}\n  {path} (con totals)")


if __name__ == "__main__":
    main()
