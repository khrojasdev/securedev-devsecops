"""Una prueba por vulnerabilidad (VULN-01 ... VULN-14) del codigo entregado.
Contra el codigo original FALLAN (la vulnerabilidad existe); contra la
version corregida PASAN (la vulnerabilidad fue mitigada)."""
import os
import re

from conftest import APP_DIR, PASSWORDS, login, try_login, update_bio


def test_vuln01_sqli_login(client):
    """SQL Injection en /login: ' OR '1'='1 o admin' -- no deben dar acceso."""
    for user, pw in (("admin' --", "x"), ("x", "' OR '1'='1")):
        r = try_login(client, user, pw)
        assert r.status_code != 302, f"login aceptado con {user!r}/{pw!r}"


def test_vuln02_sqli_en_cookie_del_dashboard(app):
    """El valor de la cookie no debe llegar al SQL del dashboard."""
    c = app.app.test_client(use_cookies=False)
    r = c.get("/dashboard", headers={"Cookie": "user_session=x'OR'1'='1"})
    assert "Panel de admin" not in r.get_data(as_text=True)


def test_vuln03_sqli_update_bio_escalada_de_rol(client, db):
    """SQLi en /update_bio: x', rol='admin no debe convertir al alumno en admin."""
    login(client, "alumno")
    update_bio(client, "x', rol='admin")
    assert db("SELECT rol FROM usuarios WHERE username = 'alumno'")["rol"] == "user"


def test_vuln04_xss_almacenado_en_biografia(client):
    login(client, "alumno")
    update_bio(client, "<script>alert(1)</script>")
    html = client.get("/dashboard").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_vuln05_ssti_en_dashboard(client):
    """{{ 7*7*1337 }} no debe evaluarse (65513) en el servidor."""
    login(client, "alumno")
    update_bio(client, "{{ 7*7*1337 }}")
    assert "65513" not in client.get("/dashboard").get_data(as_text=True)


def test_vuln06_csrf_update_bio_sin_token(client, db):
    login(client, "alumno")
    update_bio(client, "ESTA CUENTA FUE HACKEADA", with_token=False)
    assert db("SELECT bio FROM usuarios WHERE username = 'alumno'")["bio"] != "ESTA CUENTA FUE HACKEADA"


def test_vuln07_sesion_falsificable(app):
    """Una cookie user_session=admin escrita a mano no debe dar acceso como admin."""
    c = app.app.test_client(use_cookies=False)
    r = c.get("/dashboard", headers={"Cookie": "user_session=admin"})
    assert "Panel de admin" not in r.get_data(as_text=True)


def test_vuln08_cookie_con_flags_de_seguridad(client):
    r = login(client, "alumno")
    cookies = [c.lower() for c in r.headers.getlist("Set-Cookie")]
    assert cookies and all("httponly" in c and "samesite=strict" in c for c in cookies)


def test_vuln09_contrasenas_con_hash(client, db):
    stored = db("SELECT password FROM usuarios WHERE username = 'alumno'")["password"]
    assert stored not in PASSWORDS["alumno"]
    assert stored.startswith(("scrypt:", "pbkdf2:"))


def test_vuln10_sin_credenciales_por_defecto(client):
    for user, pw in (("admin", "admin123"), ("alumno", "12345")):
        assert try_login(client, user, pw).status_code != 302, f"{user}/{pw} sigue funcionando"


def test_vuln11_bloqueo_por_fuerza_bruta(client):
    codes = [try_login(client, "admin", f"clave{i}").status_code for i in range(7)]
    assert 429 in codes


def test_vuln12_configuracion_segura(client):
    src = open(os.path.join(APP_DIR, "app.py"), encoding="utf-8").read()
    assert not re.search(r"debug\s*=\s*True", src), "modo debug activo"
    h = client.get("/login").headers
    for header in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"):
        assert header in h, f"falta la cabecera {header}"
    body = client.get("/no-existe").get_data(as_text=True)
    assert "Traceback" not in body and "sqlite3" not in body


MIN_SEGURAS = {"flask": (3, 1, 1), "werkzeug": (3, 1, 4), "jinja2": (3, 1, 6)}


def _ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def test_vuln13_dependencias_fijadas_y_actualizadas():
    lines = [ln.strip() for ln in open(os.path.join(APP_DIR, "requirements.txt"))
             if ln.strip() and not ln.startswith("#")]
    pins = {}
    for ln in lines:
        assert "==" in ln, f"dependencia sin version fija: {ln}"
        name, ver = ln.split("==")
        pins[name.lower()] = ver
    for pkg, minimo in MIN_SEGURAS.items():
        assert pkg in pins and _ver(pins[pkg]) >= minimo, f"{pkg} {pins.get(pkg)} vulnerable"


def test_vuln14_registro_y_monitoreo_de_eventos(client):
    try_login(client, "admin' --", "x")
    r = client.get("/metrics")
    assert r.status_code == 200
    assert 'securedev_security_events_total{type="suspicious_input"}' in r.get_data(as_text=True)
