# Matriz de trazabilidad — Vulnerabilidad → Corrección → Verificación

Aplicación: **Sistema Académico** (código entregado en la evaluación: `app.py`, `init_db.py`,
`archivo.html`). La versión original está en la rama `baseline-vulnerable`; la corregida, en `main`.

Cada hallazgo tiene un ID único (`VULN-XX`) que aparece en: el comentario del código corregido,
el mensaje de commit, la prueba automatizada (`app/tests/test_seguridad.py`) y el informe.

| ID | Vulnerabilidad | CWE | OWASP 2021 | Ubicación en el código original | Detectado por | Corrección (`main`) | Verificación |
|---|---|---|---|---|---|---|---|
| VULN-01 | SQL Injection en el login | CWE-89 | A03 Injection | `app.py` L26 (`query = f"SELECT ... '{user}' ... '{pw}'"`) | Revisión, Bandit B608, ZAP | Consulta parametrizada `?` | `test_vuln01_sqli_login` |
| VULN-02 | SQL Injection vía cookie en el dashboard | CWE-89 | A03 Injection | `app.py` L54 (`username` de la cookie dentro del SQL) | Revisión, Bandit B608 | Usuario desde la sesión firmada + consulta parametrizada | `test_vuln02_sqli_en_cookie_del_dashboard` |
| VULN-03 | SQL Injection en `update_bio` (escalada de rol) | CWE-89 | A03 Injection | `app.py` L77 (`UPDATE ... '{nueva_bio}'`) | Revisión, Bandit B608, ZAP | `UPDATE ... WHERE id = ?` parametrizado | `test_vuln03_sqli_update_bio_escalada_de_rol` |
| VULN-04 | XSS almacenado en la biografía | CWE-79 | A03 Injection | `app.py` L56-69 (f-string con `datos['bio']`) | Revisión, ZAP 40014 | Plantilla `dashboard.html` con autoescape + CSP | `test_vuln04_xss_almacenado_en_biografia` |
| VULN-05 | Server-Side Template Injection | CWE-1336 | A03 Injection | `app.py` L69 (`render_template_string(html)` con datos del usuario) | Revisión, ZAP 90035 | Plantilla fija; la biografía es un dato | `test_vuln05_ssti_en_dashboard` |
| VULN-06 | CSRF en `update_bio` | CWE-352 | A01 Broken Access Control | `app.py` L71-78; prueba de concepto `archivo.html` | Revisión, ZAP 10202 | Token anti-CSRF por sesión + `SameSite=Strict` | `test_vuln06_csrf_update_bio_sin_token` |
| VULN-07 | Sesión falsificable (cookie = nombre de usuario) | CWE-565 / CWE-287 | A07 Ident. & Auth. Failures | `app.py` L33 (`set_cookie('user_session', username)`) | Revisión | Sesión firmada de Flask con `SECRET_KEY` de Jenkins; detección de cookies falsas | `test_vuln07_sesion_falsificable` |
| VULN-08 | Cookie sin HttpOnly / Secure / SameSite | CWE-1004 / CWE-614 | A05 Security Misconfiguration | `app.py` L33 | Revisión, ZAP 10010/10054 | `SESSION_COOKIE_HTTPONLY`, `SAMESITE=Strict`, `SECURE` con HTTPS | `test_vuln08_cookie_con_flags_de_seguridad` |
| VULN-09 | Contraseñas en texto plano | CWE-256 | A02 Cryptographic Failures | `init_db.py` L12-21; comparación en el SQL del login | Revisión | Hash scrypt con sal (`generate_password_hash` / `check_password_hash`) | `test_vuln09_contrasenas_con_hash` |
| VULN-10 | Credenciales débiles por defecto | CWE-521 / CWE-1392 | A07 Ident. & Auth. Failures | `init_db.py` L20-21 (`admin123`, `12345`) | Revisión | Claves por variable de entorno (mín. 12 caracteres) o aleatorias | `test_vuln10_sin_credenciales_por_defecto` |
| VULN-11 | Sin protección contra fuerza bruta | CWE-307 | A07 Ident. & Auth. Failures | `app.py` L19-35 (`/login`) | Revisión, simulación | Bloqueo de 5 min tras 5 fallos (HTTP 429) + alerta | `test_vuln11_bloqueo_por_fuerza_bruta`, alerta `AtaqueFuerzaBruta` |
| VULN-12 | Configuración insegura (debug, cabeceras, errores) | CWE-489 / CWE-693 / CWE-209 | A05 Security Misconfiguration | `app.py` L92 (`app.run(debug=True)`), errores SQL sin manejar | Bandit B201, ZAP 10038/10020/10021 | Gunicorn sin debug, cabeceras de seguridad, errores genéricos, contenedor no root y solo lectura | `test_vuln12_configuracion_segura` |
| VULN-13 | Dependencias sin fijar / con vulnerabilidades conocidas | CWE-1104 / CWE-1395 | A06 Vulnerable Components | `README.txt` (`pip install flask` sin versión); entorno heredado Flask 2.2.2 | pip-audit, Dependabot | Versiones parcheadas y fijadas; Dependabot semanal | Stage SCA (`pip-audit --strict`), `test_vuln13_*` |
| VULN-14 | Sin registro ni monitoreo de eventos de seguridad | CWE-778 | A09 Logging & Monitoring Failures | Toda la aplicación | Revisión | Log JSON + métricas `/metrics` + Prometheus/Grafana con alertas | `test_vuln14_registro_y_monitoreo_de_eventos` |

Observación sobre `archivo.html`: el formulario envía el campo `new_bio`, pero la aplicación lee
`nueva_bio`. Aun así el ataque funciona: `request.form.get('nueva_bio')` devuelve `None` y la biografía
de la víctima queda como `None`. La versión con el campo correcto está en `poc/csrf_poc.html`.

## Trazabilidad requisito de la evaluación → artefacto

| Requisito (pauta) | Artefacto en el repositorio | Evidencia generada |
|---|---|---|
| Pipeline con construcción, pruebas y despliegue | `Jenkinsfile`, `Dockerfile` | Stage View de Jenkins, `reports/image.txt`, `reports/deploy.txt` |
| Revisiones de seguridad continuas | Stages Pruebas, SAST, SCA, DAST | `junit.xml`, `bandit.html/json`, `pip-audit.json/md`, `zap/zap-report.*` |
| Integrar OWASP ZAP | Stage `DAST - OWASP ZAP`, `.zap/rules.tsv` | `reports/zap/zap-report.html` (publicado en Jenkins) |
| Monitorización con Grafana | `monitoring/`, métricas `/metrics` en la app | Dashboard *SecureDev - Seguridad en Producción*, alertas en Prometheus |
| Gestión de dependencias con Dependabot | `.github/dependabot.yml`, `dependency-check.yml` | PRs de Dependabot, pestaña *Security → Dependabot alerts* |
| Documentación y trazabilidad | `docs/`, `scripts/generate_traceability.py`, commits con `VULN-XX` | `reports/TRAZABILIDAD_build_N.md`, `reports/API_app.html`, `git log` |
