"""Simulacion controlada de ataques para validar la MONITORIZACION.
Repite contra produccion los ataques que funcionaban en el codigo original
del Sistema Academico y comprueba que ahora se bloquean y quedan registrados.
Uso: python simulate_attacks.py http://localhost:5000 [usuario] [password]
Solo ejecutar contra entornos propios de laboratorio."""
import re
import sys
import time

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"
USER = sys.argv[2] if len(sys.argv) > 2 else "alumno"
PASS = sys.argv[3] if len(sys.argv) > 3 else "Alumn0!Academico-2026"


def token(s, path="/login"):
    m = re.search(r'name="csrf_token" value="([^"]*)"', s.get(BASE + path, timeout=10).text)
    return m.group(1) if m else ""


def run(name, fn):
    codes = fn()
    print(f"[{time.strftime('%H:%M:%S')}] {name:<42} -> respuestas: {codes}")


def sqli_login(user, pw):
    s = requests.Session()
    return s.post(BASE + "/login", data={"username": user, "password": pw,
                                         "csrf_token": token(s)},
                  allow_redirects=False, timeout=10).status_code


# 1) SQL Injection en el login (VULN-01)
run("SQL Injection en login", lambda: [
    sqli_login(u, p) for u, p in (("admin' --", "x"), ("' OR '1'='1' --", "x"),
                                  ("x' UNION SELECT 1,2,3,4,5 --", "x"))])

# 2) Sesion falsificada: cookie user_session escrita a mano (VULN-07 / VULN-02)
run("Sesion falsificada (user_session=admin)", lambda: [
    requests.get(BASE + "/dashboard", cookies={"user_session": v},
                 allow_redirects=False, timeout=10).status_code
    for v in ("admin", "admin", "x'OR'1'='1", "admin")])

# Sesion legitima del alumno para los ataques autenticados
victim = requests.Session()
victim.post(BASE + "/login", data={"username": USER, "password": PASS,
                                   "csrf_token": token(victim)}, timeout=10)

# 3) Inyecciones en la biografia: SQLi (escalada de rol), XSS y SSTI (VULN-03/04/05)
run("SQLi / XSS / SSTI en biografia", lambda: [
    victim.post(BASE + "/update_bio", data={"nueva_bio": p,
                                            "csrf_token": token(victim, "/dashboard")},
                allow_redirects=False, timeout=10).status_code
    for p in ("x', rol='admin", "<script>alert(document.cookie)</script>", "{{7*7}}")])

# 4) CSRF: el formulario de archivo.html, sin token (VULN-06)
run("CSRF (POST /update_bio sin token)", lambda: [
    victim.post(BASE + "/update_bio", data={"nueva_bio": "ESTA CUENTA FUE HACKEADA"},
                allow_redirects=False, timeout=10).status_code for _ in range(3)])

# 5) Fuerza bruta contra admin (VULN-11)
attacker = requests.Session()
run("Fuerza bruta (8 intentos a 'admin')", lambda: [
    attacker.post(BASE + "/login", data={"username": "admin", "password": f"clave{i}",
                                         "csrf_token": token(attacker)},
                  allow_redirects=False, timeout=10).status_code
    for i in range(8)])

rol = re.search(r"<b>Rol:</b> (\w+)", victim.get(BASE + "/dashboard", timeout=10).text)
print(f"Rol del alumno tras los ataques: {rol.group(1) if rol else 'n/d'} (debe seguir siendo 'user')")
print("Simulacion terminada. Revisa Grafana: dashboard 'SecureDev - Seguridad en Produccion'.")
