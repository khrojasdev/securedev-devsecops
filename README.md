# Sistema Académico — Pipeline DevSecOps para SecureDev (OCY1102 · Evaluación Parcial N°3)

Aplicación Flask **Sistema Académico** (código vulnerable entregado en la evaluación:
login, panel con biografía, actualización de biografía y logout). Se usa para implementar un pipeline CI/CD
seguro con **Jenkins + Docker**, **OWASP ZAP**, **Dependabot**, **Prometheus/Grafana**
y documentación con trazabilidad en el SDLC.

## Estructura

| Ruta | Contenido |
|---|---|
| `app/` | Sistema Académico corregido (`app.py`, `init_db.py`, plantillas), pruebas (`tests/`) y dependencias fijadas. El código original está en la rama `baseline-vulnerable` |
| `poc/` | `archivo_original.html` (prueba de concepto CSRF entregada) y `csrf_poc.html` (con el campo corregido) |
| `Jenkinsfile` | Pipeline: Checkout → Build → Pruebas → SAST → SCA → Staging → DAST (ZAP) → Documentación → Producción → Monitorización |
| `Dockerfile` | Imagen multi-etapa (`test` y `runtime`, usuario no root, healthcheck) |
| `.zap/rules.tsv` | Reglas de ZAP: qué alertas detienen el pipeline (FAIL) y cuáles advierten (WARN) |
| `.github/dependabot.yml` | Actualización automática de dependencias pip, Docker y GitHub Actions |
| `.github/workflows/dependency-check.yml` | Verifica cada PR de Dependabot (pip check, pip-audit, pytest, Bandit) |
| `monitoring/` | Prometheus (scrape + reglas de alerta) y Grafana (datasource + dashboard provisionados) |
| `jenkins/` | Imagen de Jenkins con Docker CLI y plugins necesarios |
| `scripts/` | Sesión para ZAP autenticado, simulación de ataques y generador de trazabilidad |
| `docs/` | Matriz de trazabilidad y procedimiento de respuesta a incidentes |

## Ejecución rápida (Windows + Docker Desktop)

```powershell
docker network create securedev-net
docker compose -f jenkins/docker-compose.yml up -d --build     # Jenkins en http://localhost:8080
# Crear la credencial "securedev-secret-key" y el job Pipeline desde SCM (ver GUIA_PASO_A_PASO.md)
```

Tras un build exitoso:

- App: http://localhost:5000
- Prometheus: http://localhost:9090 (pestaña *Alerts*)
- Grafana: http://localhost:3000 → carpeta *SecureDev* → *SecureDev - Seguridad en Producción*

Simular incidentes para validar la monitorización:

```powershell
python scripts/simulate_attacks.py http://localhost:5000
```

## Pruebas locales sin Docker

```powershell
cd app
python -m venv .venv; .venv\Scripts\activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q            # 18 pruebas (4 funcionales + 14 de seguridad, una por VULN)
bandit -r . -x ./tests -ll # SAST
pip-audit -r requirements.txt   # SCA
```
