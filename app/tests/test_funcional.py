"""Pruebas funcionales: deben pasar en AMBAS versiones (la correccion no
rompe la funcionalidad del Sistema Academico)."""
from conftest import login, update_bio


def test_pagina_login_disponible(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "<form" in r.get_data(as_text=True)


def test_login_valido_muestra_panel(client):
    login(client, "alumno")
    html = client.get("/dashboard").get_data(as_text=True)
    assert "Panel de alumno" in html


def test_actualizar_biografia(client):
    login(client, "alumno")
    update_bio(client, "Me gusta programar en Python")
    assert "Me gusta programar en Python" in client.get("/dashboard").get_data(as_text=True)


def test_logout_cierra_sesion(client):
    login(client, "alumno")
    client.get("/logout")
    r = client.get("/dashboard")
    assert r.status_code == 302 and "/login" in r.headers["Location"]
