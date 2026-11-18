"""Fixtures comunes. APP_UNDER_TEST permite ejecutar la MISMA bateria de
pruebas contra la version vulnerable (evidencia 'antes') y la corregida."""
import importlib
import os
import re
import sys

import pytest

APP_DIR = os.environ.get(
    "APP_UNDER_TEST", os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
)
sys.path.insert(0, APP_DIR)

PASSWORDS = {
    "admin": ["Adm1n!SecureDev-2026", "admin123"],
    "kevin": ["Kev1n!SecureDev-2026", "kevin2024"],
    "ana": ["An4!SecureDev-2026", "ana2024"],
}


@pytest.fixture()
def app(tmp_path):
    module = importlib.import_module("app")
    module.app.config.update(TESTING=True, DB_PATH=str(tmp_path / "test.db"))
    if hasattr(module, "_failed_logins"):
        module._failed_logins.clear()
    module.init_db()
    return module


@pytest.fixture()
def client(app):
    return app.app.test_client()


def csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    m = re.search(r'name="csrf_token" value="([^"]*)"', html)
    return m.group(1) if m else ""


def login(client, user="kevin"):
    for pw in PASSWORDS[user]:
        r = client.post(
            "/login",
            data={"username": user, "password": pw, "csrf_token": csrf(client)},
        )
        if r.status_code == 302:
            return r
    raise AssertionError(f"No se pudo iniciar sesion como {user}")
