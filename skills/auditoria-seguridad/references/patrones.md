# Patrones de búsqueda por categoría

Estos patrones encuentran **candidatos**, no vulnerabilidades. Para cada coincidencia abrí el archivo y seguí el dato hasta su origen antes de reportarlo. Excluí `node_modules`, `vendor`, `build`, `dist`, `.next`, `target` y archivos minificados.

## Contenido
- Secretos
- SQL Injection
- XSS
- CSRF
- CORS
- Autenticación y autorización

## Secretos

```
(sk_live_|sk_test_|rk_live_)[0-9a-zA-Z]{10,}          # Stripe
sk-(proj-)?[A-Za-z0-9_-]{20,}                          # OpenAI
sk-ant-[A-Za-z0-9_-]{20,}                              # Anthropic
AKIA[0-9A-Z]{16}                                       # AWS
AIza[0-9A-Za-z_-]{35}                                  # Google / Firebase (la de Firebase web es pública por diseño; lo que importa son las reglas)
eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}           # JWT: decodificá el payload; si dice "role":"service_role" es crítico
-----BEGIN (RSA |EC )?PRIVATE KEY-----
(password|passwd|secret|api_?key|token)\s*[:=]\s*["'][^"']{6,}
(postgres|mysql|mongodb(\+srv)?)://[^:\s]+:[^@\s]+@     # cadenas de conexión con contraseña
```

Contexto que cambia la severidad:
- La `anon key` de Supabase y la config web de Firebase **son públicas por diseño**; no son hallazgo por sí solas. Sí lo es que las tablas no tengan RLS / reglas adecuadas.
- Una clave en un archivo de frontend (`src/`, `app/`, `pages/`, `components/`, `public/`) o en variables `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` se publica en el navegador.

## SQL Injection

Buscá consultas armadas con texto del usuario:

| Stack | Patrón sospechoso | Forma segura |
|---|---|---|
| Node (mysql, pg, sqlite) | `` query(`...${`` , `query("..." +`, `.raw(` , `$queryRawUnsafe`, `sequelize.query(` con concatenación | `query("... WHERE id = ?", [id])`, `$1`, `` $queryRaw`...` `` con tagged template |
| Python | `execute(f"`, `execute("..." %`, `execute("..." +`, `.format(` dentro de SQL, `text(f"` en SQLAlchemy, `.raw(` / `.extra(` en Django | `execute("... %s", (valor,))` |
| Java / Kotlin | `createQuery("..." +`, `createNativeQuery("..." +`, `jdbcTemplate.query("..." +`, `Statement.execute`, `@Query` con `#{` o concatenación | `PreparedStatement`, `?`/`:param`, Spring Data con parámetros |
| PHP | `mysqli_query($c, "...$_GET`, `"...{$var}..."` en SQL | PDO `prepare` + `execute` |

El nombre de tabla/columna u `ORDER BY` armado con input del usuario tampoco se puede parametrizar: debe validarse contra una lista permitida.

## XSS

| Stack | Patrón sospechoso |
|---|---|
| React / Next | `dangerouslySetInnerHTML`, `href={` con URL del usuario (`javascript:`) |
| Vue | `v-html` |
| Angular | `bypassSecurityTrust`, `[innerHTML]` |
| JS plano | `.innerHTML =`, `outerHTML`, `document.write`, `insertAdjacentHTML`, `$(...).html(` |
| Express | `res.send(` con texto que incluye `req.query`/`req.body`/`req.params` |
| Plantillas | EJS `<%-`, Handlebars `{{{`, Jinja/Django `\|safe` o `autoescape off`, Thymeleaf `th:utext`, Blade `{!!`, JSP `<%=` |

Si se usa una librería de sanitización (DOMPurify, sanitize-html, bleach) antes de insertar, no es hallazgo.

## CSRF

Primero averiguá cómo viaja la sesión:
- **Cookie** (`express-session`, `cookie-session`, `res.cookie('token'`, Spring Security con sesión, Django, Rails, NextAuth): hace falta protección. Buscá `csurf`/`csrf-csrf`, `CsrfViewMiddleware`, `protect_from_forgery`, y en Spring `csrf().disable()` / `csrf(AbstractHttpConfigurer::disable)` / `csrf(c -> c.disable())`. Mirá `sameSite` en la configuración de la cookie.
- **Header `Authorization: Bearer`** con token en memoria/localStorage: CSRF no aplica (sí aumenta el impacto de un XSS, porque el token se puede robar).

## CORS

| Stack | Patrón |
|---|---|
| Express | `cors()` sin opciones, `origin: '*'`, `origin: true`, `origin: (o, cb) => cb(null, true)`, `Access-Control-Allow-Origin` puesto a mano con `req.headers.origin` |
| Spring | `@CrossOrigin` sin `origins`, `allowedOrigins("*")`, `allowedOriginPatterns("*")` con `allowCredentials(true)` |
| Python | `CORS(app)` (Flask) sin `origins`, `allow_origins=["*"]` (FastAPI), `CORS_ALLOW_ALL_ORIGINS = True` (Django) |
| Next / Vercel | headers en `next.config.js` o `vercel.json` |

Grave: cualquier origen **y** credenciales (cookies). Menor: `*` en una API que no usa cookies.

## Autenticación y autorización

Patrones para ubicar la lógica:
- Middleware / guards: `authenticate`, `requireAuth`, `isAuthenticated`, `verifyToken`, `jwt.verify`, `getServerSession`, `@PreAuthorize`, `@Secured`, `hasRole`, `authorizeHttpRequests`, `@login_required`, `Depends(get_current_user)`.
- Roles: `role`, `isAdmin`, `is_admin`, `admin`, `permissions`.
- Contraseñas: `bcrypt`, `argon2`, `scrypt`, `PasswordEncoder` (bien) vs. `md5`, `sha1`, `createHash('sha256')` sin sal, comparación directa `password ===` (mal).
- JWT: `jwt.sign(` sin `expiresIn`, `jwt.decode(` usado en lugar de `jwt.verify(`, `algorithms` ausente, secreto literal.
- Supabase: `create table` sin `enable row level security` en `supabase/migrations/`, `using (true)`, uso de `service_role` fuera del servidor.
- Firebase: `firestore.rules` / `database.rules.json` con `if true` o reglas que solo piden `request.auth != null` sobre colecciones de otros usuarios.

Para cada ruta que modifica o devuelve datos privados, comprobá: (1) ¿pide login?, (2) ¿verifica el rol si es de admin?, (3) ¿filtra por el usuario dueño del recurso?
