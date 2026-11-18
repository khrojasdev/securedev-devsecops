# Matriz de trazabilidad — Vulnerabilidad → Corrección → Verificación

Cada hallazgo tiene un ID único (`VULN-XX`) que aparece en: el código (comentarios),
el mensaje de commit que lo corrige, la prueba automatizada que lo verifica y el
informe `Desarrollo EVA3.docx`.

| ID | Vulnerabilidad | CWE | OWASP 2021 | Ubicación (versión vulnerable) | Detectado por | Corrección | Verificación automática |
|---|---|---|---|---|---|---|---|
| VULN-01 | SQL Injection | CWE-89 | A03 Injection | `/login`, `/search`, `/dashboard` | Revisión de código, Bandit B608, ZAP 40018/40024 | Consultas parametrizadas (`?`) | `test_vuln01_*`, ZAP regla FAIL |
| VULN-02 | XSS reflejado y almacenado | CWE-79 | A03 Injection | `/search`, `note.html` (`\|safe`) | Revisión, ZAP 40012/40014 | Autoescape de Jinja2, sin `\|safe`, CSP estricta | `test_vuln02_*` |
| VULN-03 | Server-Side Template Injection | CWE-1336 | A03 Injection | `/search` (`render_template_string`) | Revisión, ZAP 90035 | Plantilla estática `search.html`, la entrada se pasa como dato | `test_vuln03_ssti_*` |
| VULN-04 | Inyección de comandos SO | CWE-78 | A03 Injection | `/ping` (`shell=True`) | Bandit B602, ZAP 90020 | Validación IP/hostname, lista de argumentos sin shell, ruta absoluta, timeout | `test_vuln04_*` |
| VULN-05 | IDOR | CWE-639 | A01 Broken Access Control | `/note/<id>` | Revisión, prueba manual | Verificación de propietario (o rol admin) → 404 | `test_vuln05_*` |
| VULN-06 | Control de acceso roto (admin) | CWE-285 | A01 Broken Access Control | `/admin` | Revisión | Decorador RBAC `role_required("admin")` → 403 | `test_vuln06_*` |
| VULN-07 | CSRF | CWE-352 | A01 Broken Access Control | Formularios POST | ZAP 10202 | Token sincronizado por sesión + cookie `SameSite=Strict` | `test_vuln07_*` |
| VULN-08 | Secreto hardcodeado | CWE-798 | A07 Ident. & Auth. Failures | `app.secret_key` | Bandit B105 | `SECRET_KEY` desde Jenkins Credentials / variable de entorno | `test_vuln08_*` |
| VULN-09 | Contraseñas en texto plano y expuestas | CWE-256 / CWE-312 | A02 Cryptographic Failures | Tabla `users`, `/admin` | Revisión | Hash scrypt con sal (`generate_password_hash`); `/admin` no expone hashes | `test_vuln09_*` |
| VULN-10 | Deserialización insegura (pickle) | CWE-502 | A08 Software & Data Integrity | `/import` | Bandit B301/B403 | JSON + validación de esquema y tamaño | `test_vuln10_*` |
| VULN-11 | SSRF | CWE-918 | A10 SSRF | `/fetch` | Revisión, ZAP 40046 | Lista blanca de hosts, solo HTTPS, sin redirecciones | `test_vuln11_*` |
| VULN-12 | Configuración insegura (debug, errores, cabeceras) | CWE-489 / CWE-209 / CWE-693 | A05 Security Misconfiguration | `app.run(debug=True)`, errores SQL al cliente | Bandit B201/B104, ZAP 10038/10020/10021/90022 | Gunicorn sin debug, manejadores de error genéricos, cabeceras de seguridad, contenedor no root y solo lectura | `test_vuln12_*`, `test_cabeceras_*`, `test_cookie_*` |
| VULN-13 | Componentes con vulnerabilidades conocidas | CWE-1395 | A06 Vulnerable Components | `requirements.txt` (7 paquetes, 38 avisos) | pip-audit, Dependabot alerts | Actualización a versiones parcheadas y fijadas; Dependabot semanal | Stage SCA (`pip-audit --strict`), workflow `dependency-check` |
| VULN-14 | Sin protección contra fuerza bruta | CWE-307 | A07 Ident. & Auth. Failures | `/login` | Revisión, simulación de ataque | Bloqueo de 5 min tras 5 fallos (IP + usuario), métricas y alerta | `test_bloqueo_por_fuerza_bruta`, alerta `AtaqueFuerzaBruta` |

## Trazabilidad requisito de la evaluación → artefacto

| Requisito (pauta) | Artefacto en el repositorio | Evidencia generada |
|---|---|---|
| Pipeline con construcción, pruebas y despliegue | `Jenkinsfile`, `Dockerfile` | Stage View de Jenkins, `reports/image.txt`, `reports/deploy.txt` |
| Revisiones de seguridad continuas | Stages Pruebas, SAST, SCA, DAST | `junit.xml`, `bandit.html/json`, `pip-audit.json/md`, `zap/zap-report.*` |
| Integrar OWASP ZAP | Stage `DAST - OWASP ZAP`, `.zap/rules.tsv` | `reports/zap/zap-report.html` (publicado en Jenkins) |
| Monitorización con Grafana | `monitoring/`, métricas `/metrics` en la app | Dashboard *SecureDev - Seguridad en Producción*, alertas en Prometheus |
| Gestión de dependencias con Dependabot | `.github/dependabot.yml`, `dependency-check.yml` | PRs de Dependabot, pestaña *Security → Dependabot alerts* |
| Documentación y trazabilidad | `docs/`, `scripts/generate_traceability.py`, commits con `VULN-XX` | `reports/TRAZABILIDAD_build_N.md`, `reports/API_app.html`, `git log` |
