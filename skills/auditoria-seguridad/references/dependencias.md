# Escaneo de dependencias por ecosistema

Elegí la fila según los manifiestos que encontraste. Si hay varios (un frontend npm y un backend Gradle, por ejemplo), escaneá cada uno.

Antes de correr nada, verificá qué herramientas hay: `command -v npm pnpm yarn pip-audit osv-scanner trivy docker gradle mvn`.

| Manifiesto / lockfile | Herramienta preferida | Comando |
|---|---|---|
| `package-lock.json` | npm | `npm audit --json` |
| `pnpm-lock.yaml` | pnpm | `pnpm audit --json` |
| `yarn.lock` (Yarn 1) | yarn | `yarn audit --json` |
| `yarn.lock` (Yarn 2+, hay `.yarnrc.yml`) | yarn | `yarn npm audit --all --recursive --json` |
| `requirements.txt`, `pyproject.toml`, `poetry.lock` | pip-audit | `pip-audit -r requirements.txt -f json` |
| `build.gradle`, `build.gradle.kts` | OWASP dependency-check u osv-scanner | ver sección Gradle |
| `pom.xml` | OWASP dependency-check | `mvn org.owasp:dependency-check-maven:check -Dformat=JSON` |
| `composer.lock` | composer | `composer audit --format=json` |
| `Gemfile.lock` | bundler-audit | `bundle-audit check --update` |
| `go.mod` | govulncheck | `govulncheck ./...` |
| `*.csproj` | dotnet | `dotnet list package --vulnerable --include-transitive` |
| `Cargo.lock` | cargo-audit | `cargo audit --json` |

**Comodín para cualquier ecosistema:** `osv-scanner scan source -r .` (o `trivy fs --scanners vuln .`) lee lockfiles de casi todos los lenguajes sin ejecutar el proyecto. Si no está instalado pero hay Docker:
`docker run --rm -v "$PWD":/src ghcr.io/google/osv-scanner scan source -r /src`

## npm sin lockfile

`npm audit` exige `package-lock.json`. Para no escribir en el proyecto ni ejecutar scripts del paquete, generalo en una carpeta temporal:

```bash
TMP=$(mktemp -d) && cp package.json "$TMP"/ && (cd "$TMP" && npm install --package-lock-only --ignore-scripts && npm audit --json)
```

Aclará en el informe que las versiones resueltas son las de hoy, no necesariamente las que corren en producción.

## Gradle

Ninguna opción es perfecta; elegí según lo disponible y explicá la elección:

1. **Hay `gradle.lockfile`** → `osv-scanner scan source -r .` lo lee directo. Es lo más limpio.
2. **Hay Gradle/`./gradlew` y la persona acepta ejecutar el build** → OWASP dependency-check con un init script, para no tocar `build.gradle`:
   ```bash
   cat > "$TMPDIR/dc.gradle" <<'EOF'
   initscript {
     repositories { gradlePluginPortal() }
     dependencies { classpath 'org.owasp:dependency-check-gradle:13.0.0' }
   }
   allprojects { apply plugin: org.owasp.dependencycheck.gradle.DependencyCheckPlugin }
   EOF
   ./gradlew --init-script "$TMPDIR/dc.gradle" dependencyCheckAnalyze
   ```
   Advertencias: ejecutar `./gradlew` corre el código de los scripts de build (pedí permiso); la primera corrida descarga la base NVD y puede tardar mucho sin una API key (`NVD_API_KEY`). Revisá la última versión del plugin si esa falla.
3. **No hay nada instalado** → extraé las dependencias declaradas (`group:artifact:version`) de `build.gradle` y consultalas con el script incluido:
   ```bash
   python3 scripts/osv_consulta.py Maven org.springframework.boot:spring-boot-starter-web 2.5.0 Maven com.h2database:h2 1.4.197
   ```
   La ruta `scripts/` es relativa a la carpeta del skill. **Si no hay Python**, consultá la misma base directamente con `curl`: el primer pedido devuelve los IDs de las vulnerabilidades por paquete y el segundo el detalle de cada una (campo `database_specific.severity` y versiones `fixed` en `affected[].ranges[].events`):
   ```bash
   curl -s -X POST https://api.osv.dev/v1/querybatch -d '{"queries":[{"package":{"ecosystem":"Maven","name":"com.h2database:h2"},"version":"1.4.197"}]}'
   curl -s https://api.osv.dev/v1/vulns/GHSA-xxxx-xxxx-xxxx
   ```
   Esto solo cubre dependencias directas con versión explícita. Las que heredan versión de un BOM/plugin (Spring Boot `io.spring.dependency-management`) toman la versión del BOM: indicala si podés deducirla (la versión del plugin de Spring Boot define la de sus starters) o listala como "no verificada". Decí en "Límites" que las transitivas no se revisaron.

## Python sin pip-audit

`osv-scanner` lee `requirements.txt` y `poetry.lock`. Sin herramientas, usá `scripts/osv_consulta.py` (o `curl`, como en la sección Gradle) con ecosistema `PyPI` para las dependencias con versión fija (`paquete==x.y.z`).

## Cómo leer y resumir

- Agrupá por paquete: un mismo paquete viejo suele traer 5–10 avisos; para la persona importa "actualizar X de 1.2 a 1.9", no la lista de CVEs.
- `arreglada_en` / `fixAvailable` puede listar varias ramas (ej. log4j `2.3.1`, `2.12.2`, `2.15.0`): recomendá la versión arreglada más reciente de una rama igual o superior a la instalada.
- Separá dependencias de producción y de desarrollo (`devDependencies`, `testImplementation`): una vulnerabilidad en una herramienta de build rara vez afecta a los usuarios finales.
- Si es rápido verificarlo, decí si el código usa la función afectada (ej. `_.template` en lodash). No es obligatorio, pero ayuda a priorizar.
