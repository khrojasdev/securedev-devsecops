"""Obtiene una cookie de sesion valida para que OWASP ZAP escanee las
paginas autenticadas. Uso: python get_session.py <base_url> <usuario> <password>"""
import re
import sys

import requests

base, user, password = sys.argv[1].rstrip("/"), sys.argv[2], sys.argv[3]
s = requests.Session()
html = s.get(f"{base}/login", timeout=10).text
m = re.search(r'name="csrf_token" value="([^"]*)"', html)
data = {"username": user, "password": password, "csrf_token": m.group(1) if m else ""}
r = s.post(f"{base}/login", data=data, allow_redirects=False, timeout=10)
if r.status_code != 302:
    sys.exit("No se pudo iniciar sesion para el escaneo autenticado")
print(f"session={s.cookies.get('session')}")
