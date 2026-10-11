---
name: auditoria-seguridad
description: Diagnóstico de seguridad de un proyecto de software ya escrito (típicamente generado con IA por alguien sin experiencia en programación), explicado en lenguaje simple. Detecta la tecnología, escanea dependencias vulnerables (npm audit, pip-audit, osv-scanner, OWASP dependency-check para Gradle/Maven), busca secretos expuestos, revisa autenticación, autorización y roles, e inspecciona SQL injection, XSS, CSRF y CORS. Entrega una página visual con los riesgos para el negocio y un informe técnico para quien los arregle. Usar siempre que el usuario pida auditar, revisar o diagnosticar la seguridad de un proyecto o repositorio, quiera saber si una app "es segura", si el código que le hizo la IA (Lovable, Bolt, Cursor, v0, ChatGPT, Claude) tiene problemas, o vaya a publicar/vender una app y quiera revisarla antes, aunque no use la palabra "auditoría".
---

# Auditoría de seguridad para proyectos hechos con IA

La persona que pide esto suele ser dueña de un negocio que hizo (o le hicieron) una app con IA y no sabe leer código. Necesita dos cosas: saber **qué tan expuesta está** y **qué hacer primero**. Un informe lleno de jerga o con 40 hallazgos sin prioridad no le sirve; tres problemas reales bien explicados, sí.

## Reglas de trabajo

- **Solo lectura.** No modifiques el código, los archivos de build ni las dependencias del proyecto. El objetivo es un diagnóstico; los arreglos se hacen después, si la persona los pide. Lo único que se escribe son los entregables del paso 7.
- **No ejecutes código del proyecto.** `npm install` corre scripts arbitrarios del paquete (`postinstall`) y levantar la app puede conectarse a bases de datos reales. Los escáneres de dependencias leen manifiestos y lockfiles; con eso alcanza. Si un escáner necesita un lockfile que no existe, mirá `references/dependencias.md`.
- **No instales herramientas sin preguntar.** Si falta un escáner, decí cuál falta, cómo se instala y ofrecé la alternativa (Docker, otra herramienta o revisión manual). Seguí con el resto de la auditoría mientras tanto.
- **Sin evidencia no hay hallazgo.** Cada problema lleva archivo y línea, y una explicación de por qué es explotable (de dónde viene el dato, a dónde llega). Si algo es sospechoso pero no pudiste confirmarlo, marcalo como "a verificar", no como vulnerabilidad. Antes de decir que el código contradice la documentación, leé la documentación completa: a veces describe más de una variante. Los falsos positivos destruyen la confianza en el informe.
- **No ataques sistemas reales.** Nada de probar inyecciones contra URLs de producción ni usar credenciales que encuentres. Si encontrás una clave, reportala enmascarada (`sk_live_…a9F2`).

## Proceso

### 1. Reconocimiento: qué es y qué hace

Antes de buscar fallas, entendé el proyecto. Leé el README si existe, los manifiestos (`package.json`, `build.gradle`, `pom.xml`, `requirements.txt`, `pyproject.toml`, `composer.json`, `Gemfile`, `go.mod`…), la estructura de carpetas y los puntos de entrada.

Anotá:
- Lenguajes, frameworks y base de datos.
- Si hay backend propio o si el frontend habla directo con un servicio (Supabase, Firebase). Esto cambia todo: sin backend, la seguridad depende de las reglas del servicio (RLS, Security Rules), no del código.
- Qué hace la app en 2–3 frases para alguien no técnico ("es una tienda online donde los clientes se registran, compran y un administrador carga productos").
- Qué datos sensibles maneja (datos personales, pagos, salud) — define cuánto importa cada hallazgo.
- Lista de rutas/endpoints y quién debería poder usarlas.

### 2. Dependencias vulnerables

Cada ecosistema tiene su escáner. Consultá `references/dependencias.md` para el comando exacto, cómo leer la salida y qué hacer si falta el lockfile o la herramienta. Resumí por severidad (crítica/alta/media/baja), y para las críticas y altas indicá paquete, versión instalada, versión que lo arregla y si el código realmente usa la parte vulnerable cuando sea fácil de ver.

### 3. Secretos expuestos

En proyectos hechos con IA este es el problema más frecuente y el más caro: claves de API, contraseñas de base de datos o claves de servicio pegadas en el código, o un `.env` subido al repositorio. Buscá:
- Archivos `.env*` versionados (si hay `.git`, `git ls-files | grep -i env`) y si `.gitignore` los excluye.
- Patrones de claves en el código (ver `references/patrones.md`, sección Secretos). Si `gitleaks` está instalado, usalo.
- Claves que llegan al navegador: variables `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` o claves escritas en componentes de frontend. Una clave `service_role` de Supabase o una clave secreta de Stripe/OpenAI en el frontend es crítica: cualquiera la ve desde el navegador.
- El historial de git, si existe: una clave borrada en el último commit sigue en los anteriores (`git log -p -S 'sk_' --all | head`).

### 4. Autenticación (quién sos)

Identificá el mecanismo: sesiones con cookie, JWT, OAuth, proveedor externo (Supabase Auth, Firebase Auth, Auth0, Clerk, NextAuth, Spring Security…). Revisá:
- Contraseñas: ¿se guardan con hash fuerte (bcrypt, argon2, scrypt) o en texto plano / MD5 / SHA1?
- JWT: secreto fijo en el código o débil (`"secret"`, `"changeme"`), algoritmo `none` aceptado, sin expiración, guardado en `localStorage`.
- Cookies de sesión: flags `HttpOnly`, `Secure`, `SameSite`.
- Login sin límite de intentos, recuperación de contraseña predecible, endpoints que deberían requerir login y no lo hacen.

### 5. Autorización y roles (qué podés hacer)

Acá viven los errores más graves de las apps generadas con IA, porque la IA suele esconder botones en el frontend y olvidar proteger el backend. Revisá:
- ¿Existen roles (admin, usuario, vendedor…)? ¿Dónde se definen y dónde se verifican?
- **Chequeos solo en el frontend**: si el botón de "Admin" se oculta en React pero el endpoint `/api/admin/...` no verifica el rol en el servidor, cualquiera puede llamarlo directamente.
- **Acceso a datos ajenos (IDOR)**: endpoints como `/api/pedidos/:id` que devuelven el recurso sin comprobar que pertenece al usuario logueado.
- El rol viene del cliente (campo `role` en el body del registro, en un header o en el JWT sin verificar).
- Supabase: tablas sin RLS habilitado o con políticas `using (true)`. Firebase: reglas `allow read, write: if true` o solo `if request.auth != null` para datos privados.

Armá una tabla breve de endpoints sensibles → protección esperada → protección real.

### 6. Inyecciones y configuración web

Consultá `references/patrones.md` para los patrones de búsqueda por framework. Para cada candidato, seguí el dato: si viene del usuario (body, query, params, headers, cookies) y llega al punto peligroso sin sanitizar, es un hallazgo; si es una constante o ya está validado, no lo es.

- **SQL Injection**: consultas armadas concatenando texto o con template strings en lugar de parámetros (`?`, `$1`, `:nombre`), incluido el uso de "raw queries" dentro de ORMs.
- **XSS**: HTML del usuario insertado sin escapar (`dangerouslySetInnerHTML`, `v-html`, `innerHTML`, `|safe`, `th:utext`, `res.send` con texto del usuario).
- **CSRF**: solo aplica si la autenticación viaja en cookies. Si hay cookies de sesión y los endpoints que modifican datos no tienen token CSRF ni `SameSite=Lax/Strict`, es un hallazgo. Con JWT en header `Authorization` el riesgo es bajo; explicá por qué en vez de reportarlo.
- **CORS**: `origin: '*'` o reflejar cualquier origen, especialmente combinado con `credentials: true`. CORS abierto en una API pública sin cookies no es grave; decilo así.
- Extras que valen mencionar si los ves: errores que muestran stack traces al usuario, modo debug en producción, falta de headers de seguridad (helmet), subida de archivos sin validar tipo/tamaño.

### 7. Entregables

La persona que pidió la auditoría probablemente no lea código, pero alguien va a tener que arreglar los problemas. Por eso hay dos entregables, y los dos salen de un único JSON que escribís vos y que un script convierte:

- `AUDITORIA-SEGURIDAD.html`: una página visual para el dueño. Muestra riesgos de negocio, qué podría pasar y qué arreglar primero, sin jerga técnica.
- `AUDITORIA-SEGURIDAD.md`: el detalle técnico con archivo y línea, para quien haga los arreglos.

La página ya está diseñada en `assets/plantilla.html`: se dibuja sola en el navegador a partir del JSON que lleva adentro. No escribas HTML: eso garantiza el mismo diseño en cada corrida y te ahorra muchos tokens.

Los archivos del skill están en `${CLAUDE_SKILL_DIR}`, la carpeta donde está este SKILL.md.

**Paso a paso**
1. Escribí `auditoria-seguridad.json` en la raíz del proyecto auditado (o donde el usuario indique) con el formato de abajo.
2. Generá los entregables. Fijate si hay Python (`python3 --version`; en Windows también `python --version`):
   - **Con Python:** corré `python3 "${CLAUDE_SKILL_DIR}/scripts/generar_informe.py" <ruta>/auditoria-seguridad.json`. El script valida el JSON (si tiene errores, los lista todos: corregilos y volvé a correr), calcula `totals` y `repo.commit`, y genera el HTML y el MD.
   - **Sin Python:** no le pidas a la persona que lo instale; el skill funciona igual:
     1. Agregá vos `totals` al JSON (cantidad de riesgos por `urgency` y de hallazgos por `severity`, con el formato de abajo) y, si hay git, `repo.commit` (`git rev-parse --short HEAD`).
     2. Copiá `${CLAUDE_SKILL_DIR}/assets/plantilla.html` como `AUDITORIA-SEGURIDAD.html` junto al JSON.
     3. En la copia, reemplazá la línea `__DATOS__` por el contenido completo del JSON, **escribiendo cada `<` como `\u003c`**. Es la forma válida en JSON de escribir ese carácter, y evita que un texto como `</script>` (frecuente al citar código) rompa la página.
     4. Escribí `AUDITORIA-SEGURIDAD.md` con esta estructura: título, fecha, semáforo y commit; el veredicto; una tabla de hallazgos (ID, severidad, categoría, dónde, riesgo al que pertenece); el detalle de cada hallazgo (dónde, causa, cómo se arregla); dependencias; herramientas; lo que está bien; límites.
3. Abrí el HTML para la persona (`open` en macOS, `xdg-open` en Linux, `start` en Windows). Si la página muestra "No se pudo leer el informe", el JSON insertado tiene un error de sintaxis: corregilo en el HTML.

**Cómo pensar los riesgos.** Un *hallazgo* es técnico ("SQL injection en server.js:44"). Un *riesgo* es lo que le pasa al negocio ("cualquiera puede entrar como administrador"). Agrupá los hallazgos que llevan a la misma consecuencia en un solo riesgo: el dueño necesita 3–7 riesgos claros, no 15 hallazgos. Escribí los riesgos para alguien que nunca programó:
- `title`: la consecuencia, en una frase y sin términos técnicos. Mal: "IDOR en /api/pedidos". Bien: "Un cliente puede ver los pedidos de otros".
- `scenario`: un escenario concreto con su tienda, sus clientes y su plata, no la mecánica del ataque. Sin nombres de librerías, archivos, herramientas ni siglas (nada de "axios", "RLS", "HTML sin escapar"): eso va en los hallazgos. Si un término es inevitable, explicalo con palabras comunes ("la clave maestra de tu base de datos").
- Sé honesto con la probabilidad. Si el riesgo requiere condiciones difíciles (ser usuario de una lista cerrada, adivinar un identificador aleatorio), bajá `actor` o `severity` y decilo en el texto. Si una clave parece de ejemplo o de prueba, decilo en vez de presentarla como una filtración real.
- No asumas el país de la persona. Si hay datos personales o de salud, mencioná "las leyes de protección de datos" en general, salvo que sepas dónde opera.

**Formato del JSON**

Las claves y los valores fijos van en inglés porque los lee una máquina (el script, y más adelante otros agentes). Los textos libres van en el idioma de la persona, porque son los que ella lee.

```json
{
  "version": 1,
  "project": "Nombre visible del proyecto",
  "date": "AAAA-MM-DD",
  "repo": { "path": "/ruta/absoluta/al/proyecto" },
  "stack": ["node", "express", "sqlite"],
  "status": "red | yellow | green",
  "verdict": "Una o dos frases para el dueño: qué tan expuesto está y si puede lanzar o seguir así.",
  "purpose": "Qué hace la app, en 2–3 frases sin jerga.",
  "assets": ["Datos personales de clientes", "Pagos"],
  "risks": [
    {
      "id": "R1",
      "title": "Un cliente puede ver los pedidos de otros",
      "scenario": "Escenario concreto en lenguaje simple.",
      "affects": ["Tus clientes", "Tu negocio"],
      "impacts": ["data", "money", "legal", "reputation", "outage", "takeover"],
      "actor": "anyone | user | insider",
      "severity": "high | medium | low",
      "urgency": "now | soon | later",
      "effort": "hours | days | weeks",
      "findings": ["H1", "H2"]
    }
  ],
  "findings": [
    {
      "id": "H1",
      "severity": "critical | high | medium | low",
      "confidence": "confirmed | suspected",
      "category": "sqli | xss | csrf | cors | authn | authz | secrets | dependencies | config",
      "title": "Título técnico breve",
      "locations": ["ruta/archivo.js:42"],
      "cause": "Explicación técnica: de dónde viene el dato y a dónde llega.",
      "fix": "Cambio concreto, con código corto si ayuda."
    }
  ],
  "dependencies": {
    "tool": "npm audit",
    "summary": "27 avisos: 4 críticos, 13 altos.",
    "packages": [{ "name": "ejs", "version": "3.1.6", "severity": "critical", "fixed": "3.1.10" }]
  },
  "tools": { "used": ["npm audit"], "missing": ["osv-scanner", "gitleaks"] },
  "strengths": ["Prácticas correctas encontradas, en lenguaje simple."],
  "limitations": ["Qué quedó fuera y qué recomendás para cubrirlo."]
}
```

Con Python, no escribas `totals` ni `repo.commit`: el script los calcula y los agrega al JSON. Sin Python, agregalos vos con este formato: `"totals": {"risks": {"now": 3, "soon": 1, "later": 0}, "findings": {"critical": 1, "high": 2, "medium": 1, "low": 0}}`.

Significado de los valores fijos:
- `status`: `red` (hay riesgos graves al alcance de cualquiera o de un usuario común), `yellow` (hay problemas reales pero acotados), `green` (nada relevante).
- `impacts`: `data` (robo o filtración), `money` (pérdida directa), `legal` (multas, reclamos), `reputation`, `outage` (la app deja de funcionar), `takeover` (alguien toma el control de la app o del servidor).
- `actor`: `anyone` (sin cuenta, desde internet), `user` (con una cuenta normal), `insider` (alguien con acceso al código, al servidor o al equipo).
- `severity` del riesgo: qué tan grave sería para el negocio si pasa (`high`, `medium`, `low`).
- `urgency`: `now` (antes de lanzar, o de inmediato si ya está en producción), `soon` (próximas semanas), `later` (mejora).
- `effort`: cuánto lleva arreglarlo a alguien que sabe (`hours`, `days`, `weeks`).
- `severity` del hallazgo: **critical** si es explotable hoy, sin login o con login trivial, con impacto en datos o dinero; **high** si es explotable con alguna condición (por ejemplo, un usuario registrado accediendo a datos ajenos); **medium** si requiere combinar factores o el impacto es limitado; **low** si es una buena práctica faltante sin vía de ataque clara.
- `confidence`: `confirmed` si seguiste el dato de punta a punta en el código; `suspected` si es probable pero no pudiste confirmarlo (el "a verificar" de las reglas de trabajo).
- `category`: `authn` es autenticación (quién sos: login, contraseñas, sesiones, tokens); `authz` es autorización (qué podés hacer: roles, datos ajenos). Lo que no encaja en ninguna otra va en `config`.

`stack`, `dependencies`, `tools`, `strengths` y `limitations` son opcionales, pero casi siempre hay algo para poner. Todo hallazgo debería pertenecer a algún riesgo; los menores pueden ir juntos en un riesgo de urgencia `later`.

Antes de generar, releé el JSON entero como lo leería el dueño. El veredicto y el mensaje final no pueden prometer más ni menos que los riesgos: si un riesgo dice `days`, no digas "todo se arregla en horas". Un título tampoco puede afirmar más que su texto: si la clave parece de ejemplo, el título no dice "tu clave quedó expuesta".

Cerrá el mensaje en el chat con el semáforo, los riesgos de urgencia `now` en una frase cada uno y las rutas de los dos archivos.
