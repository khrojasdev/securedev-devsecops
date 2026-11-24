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
| `IntentosDeInyeccion` | `suspicious_input` (login o biografía) | Revisar el campo `sample` del log para identificar el payload (SQLi, XSS, SSTI) |
| `SesionFalsificada` | `session_forgery` | Cookie `user_session` escrita a mano o sesión con firma inválida: identificar la IP |
| `IntentosCSRF` | `csrf_rejected` | POST sin token válido: revisar el origen (página como `archivo.html`) |
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
