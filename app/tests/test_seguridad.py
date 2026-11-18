"""Pruebas automatizadas de seguridad (una por vulnerabilidad, ID VULN-XX).
En la version vulnerable FALLAN (evidencian la falla); en la corregida PASAN."""
import base64
import pickle

from conftest import csrf, login


def test_vuln01_sqli_bypass_login(client):
    r = client.post("/login", data={"username": "admin' --", "password": "x",
                                    "csrf_token": csrf(client)})
    assert r.status_code != 302, "SQLi permite iniciar sesion sin contrasena"


def test_vuln01_sqli_union_en_busqueda(client):
    login(client, "kevin")
    payload = "' UNION SELECT id, id, password, email FROM users --"
    html = client.get("/search", query_string={"q": payload}).get_data(as_text=True)
    assert "admin123" not in html and "scrypt:" not in html


def test_vuln02_xss_reflejado_escapado(client):
    login(client, "kevin")
    html = client.get("/search", query_string={"q": "<script>alert(1)</script>"}).get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_vuln02_xss_almacenado_escapado(client):
    login(client, "kevin")
    token = csrf(client, "/dashboard")
    client.post("/note/new", data={"title": "x", "content": "<img src=x onerror=alert(1)>",
                                   "csrf_token": token})
    html = client.get("/note/4").get_data(as_text=True)
    assert "<img src=x onerror=alert(1)>" not in html


def test_vuln03_ssti_no_evalua_expresiones(client):
    login(client, "kevin")
    html = client.get("/search", query_string={"q": "{{7*7}}"}).get_data(as_text=True)
    assert "49" not in html


def test_vuln04_inyeccion_comandos(client):
    login(client, "kevin")
    r = client.get("/ping", query_string={"host": "127.0.0.1; echo PWNED-$((6*7))"})
    assert "PWNED-42" not in r.get_data(as_text=True)
    assert r.status_code == 400


def test_vuln05_idor_nota_ajena(client):
    login(client, "kevin")
    r = client.get("/note/3")  # nota de Ana
    assert r.status_code == 404
    assert "Datos personales de Ana" not in r.get_data(as_text=True)


def test_vuln06_admin_solo_para_rol_admin(client):
    login(client, "kevin")
    assert client.get("/admin").status_code == 403


def test_vuln07_csrf_sin_token_rechazado(client):
    login(client, "kevin")
    r = client.post("/note/new", data={"title": "csrf", "content": "csrf"})
    assert r.status_code == 400


def test_vuln08_secret_key_no_hardcodeada(app):
    assert app.app.secret_key != "securedev123"
    assert len(app.app.secret_key) >= 32


def test_vuln09_contrasenas_con_hash(app, client):
    login(client, "admin")
    html = client.get("/admin").get_data(as_text=True)
    assert "admin123" not in html and "Adm1n!" not in html
    import sqlite3
    db = sqlite3.connect(app.app.config["DB_PATH"])
    stored = db.execute("SELECT password FROM users WHERE username='kevin'").fetchone()[0]
    assert stored.startswith(("scrypt:", "pbkdf2:"))


class _Exploit:
    def __reduce__(self):
        import os
        return (os.getpid, ())


def test_vuln10_deserializacion_insegura(client):
    login(client, "kevin")
    token = csrf(client, "/dashboard")
    payload = base64.b64encode(pickle.dumps([_Exploit()])).decode()
    r = client.post("/import", data={"data": payload, "csrf_token": token})
    assert r.status_code == 400


def test_vuln11_ssrf_bloqueado(client):
    login(client, "kevin")
    r = client.get("/fetch", query_string={"url": "http://169.254.169.254/latest/meta-data/"})
    assert r.status_code == 400


def test_vuln12_errores_sin_detalle_interno(client):
    r = client.post("/login", data={"username": "'", "password": "x", "csrf_token": csrf(client)})
    body = r.get_data(as_text=True)
    assert "sqlite3" not in body and "SELECT" not in body


def test_cabeceras_de_seguridad(client):
    r = client.get("/login")
    for h in ("Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
              "Referrer-Policy"):
        assert h in r.headers, f"Falta cabecera {h}"


def test_cookie_de_sesion_samesite(client):
    login(client, "kevin")
    cookie = client.get_cookie("session")
    assert cookie is not None and cookie.same_site == "Strict" and cookie.http_only


def test_bloqueo_por_fuerza_bruta(client):
    for _ in range(5):
        client.post("/login", data={"username": "kevin", "password": "mala",
                                    "csrf_token": csrf(client)})
    r = client.post("/login", data={"username": "kevin", "password": "mala",
                                    "csrf_token": csrf(client)})
    assert r.status_code == 429
