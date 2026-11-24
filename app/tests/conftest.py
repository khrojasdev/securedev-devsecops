"""Fixtures comunes. APP_UNDER_TEST permite ejecutar la MISMA bateria de
pruebas contra el codigo original entregado (evidencia "antes") y contra la
version corregida ("despues")."""
import importlib
import os
import re
import sqlite3
import sys

import pytest

APP_DIR = os.environ.get(
    "APP_UNDER_TEST", os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
sys.path.insert(0, APP_DIR)

# Claves fuertes que usa la version corregida (variables de entorno) y claves
# por defecto del codigo original (admin123 / 12345).
STRONG = {"admin": "Adm1n!Academico-2026", "alumno": "Alumn0!Academico-2026"}
PASSWORDS = {"admin": [STRONG["admin"], "admin123"], "alumno": [STRONG["alumno"], "12345"]}
DB_NAME = "vulnerable.db"  # nombre que usa el codigo original


@pytest.fixture()
def app(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)  # el codigo original usa vulnerable.db en el directorio actual
    monkeypatch.setenv("DB_PATH", str(tmp_path / DB_NAME))
    monkeypatch.setenv("ADMIN_PASSWORD", STRONG["admin"])
    monkeypatch.setenv("ALUMNO_PASSWORD", STRONG["alumno"])
    importlib.import_module("init_db").crear_base_de_datos()
    module = importlib.import_module("app")
    module.app.config.update(TESTING=True)
    if hasattr(module, "_failed_logins"):
        module._failed_logins.clear()
    return module


@pytest.fixture()
def client(app):
    return app.app.test_client()


@pytest.fixture()
def db(tmp_path, app):
    def query(sql, *args):
        con = sqlite3.connect(tmp_path / DB_NAME)
        con.row_factory = sqlite3.Row
        row = con.execute(sql, args).fetchone()
        con.close()
        return row

    return query


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]*)"', html)
    return m.group(1) if m else ""


def try_login(client, user, password):
    return client.post(
        "/login", data={"username": user, "password": password, "csrf_token": csrf(client)}
    )


def login(client, user="alumno"):
    for pw in PASSWORDS[user]:
        r = try_login(client, user, pw)
        if r.status_code == 302:
            return r
    raise AssertionError(f"No se pudo iniciar sesion como {user}")


def update_bio(client, texto, with_token=True):
    data = {"nueva_bio": texto}
    if with_token:
        data["csrf_token"] = csrf(client, "/dashboard")
    return client.post("/update_bio", data=data)
