# Procedimiento de respuesta a incidentes de seguridad (producción)

Basado en las fases de NIST SP 800-61: Preparación → Detección y análisis →
Contención, erradicación y recuperación → Actividades post-incidente.

## 1. Preparación
- Métricas de seguridad expuestas por la app en `/metrics` (`securedev_security_events_total{type}`,
  `securedev_login_attempts_total{result}`, latencia y códigos HTTP).
- Logs de seguridad en formato JSON (stdout del contenedor `securedev-prod`).
- Reglas de alerta en `monitoring/prometheus/alert_rules.yml`, visibles en Grafana.

## 2. Detección y análisis

| Alerta | Señal | Primer análisis |
|---|---|---|
| `AtaqueFuerzaBruta` | > 5 logins fallidos/bloqueados en 2 min | `docker logs securedev-prod \| findstr login_failure` → IP y usuario atacado |
| `IntentosDeInyeccion` | `suspicious_input`, `command_injection_blocked`, `deserialization_rejected` | Revisar campo `sample` del log para identificar el payload (SQLi, XSS, SSTI, comandos) |
| `ViolacionesControlDeAcceso` | `idor_attempt`, `access_denied` | Identificar el usuario autenticado que enumera recursos o intenta entrar a `/admin` |
| `IntentosSSRFoCSRF` | `ssrf_blocked`, `csrf_rejected` | Revisar URLs objetivo (metadata cloud, `file://`) u origen de los POST |
| `SecureDevCaida` / `TasaAltaErrores5xx` | `up == 0` o 5xx > 0,1/s | `docker ps`, `docker logs`, healthcheck |

## 3. Contención, erradicación y recuperación
1. **Contener**: el bloqueo automático actúa ante fuerza bruta; si persiste, bloquear la IP en el
   firewall/proxy y deshabilitar o forzar cambio de contraseña de la cuenta atacada.
2. **Erradicar**: si un ataque tuvo éxito, crear issue con ID `INC-AAAA-NN`, corregir el código en una
   rama `fix/INC-...`, agregar una prueba que reproduzca el ataque y pasar por el pipeline completo.
3. **Recuperar**: desplegar la imagen corregida (el pipeline solo despliega si todos los controles pasan)
   y verificar en Grafana que las métricas vuelven a la normalidad. Si es necesario, volver a la imagen
   anterior: `docker run ... securedev:<build_anterior>`.

## 4. Post-incidente
- Registrar el incidente en la bitácora (abajo) con línea de tiempo, impacto y acciones.
- Ajustar umbrales de alerta y agregar la nueva prueba a `tests/test_seguridad.py`.

## Bitácora de incidentes

| ID | Fecha/hora | Alerta | Descripción | Acciones | Estado |
|---|---|---|---|---|---|
| INC-2026-01 | 2026-11-20 12:55:19 | AtaqueFuerzaBruta | 8 intentos sobre `admin` desde una IP; 3 bloqueados (HTTP 429) | Bloqueo automático 5 min, revisión de logs, sin acceso indebido | Cerrado |
| INC-2026-02 | 2026-11-20 12:55:59 | IntentosDeInyeccion | Payloads SQLi/XSS/SSTI y de comandos en `/login`, `/search`, `/ping` | Entradas rechazadas o neutralizadas; sin impacto | Cerrado |
| INC-2026-03 | 2026-11-20 12:56:04 | ViolacionesControlDeAcceso | Usuario `kevin` enumeró notas ajenas e intentó `/admin` (403/404) | Accesos denegados; usuario bajo revisión | Cerrado |
| INC-2026-04 | 2026-11-20 12:56:04 | IntentosSSRFoCSRF | Intento SSRF a 169.254.169.254 y POST sin token CSRF | Solicitudes bloqueadas (400) | Cerrado |
