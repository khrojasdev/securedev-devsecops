"""Pruebas funcionales: la correccion de seguridad no rompe la aplicacion."""
from conftest import csrf, login


def test_login_valido_redirige_a_dashboard(client):
    r = login(client, "kevin")
    assert r.headers["Location"].endswith("/dashboard")


def test_dashboard_muestra_solo_mis_notas(client):
    login(client, "kevin")
    html = client.get("/dashboard").get_data(as_text=True)
    assert "Pendientes" in html
    assert "Privado de Ana" not in html


def test_crear_y_buscar_nota(client):
    login(client, "kevin")
    token = csrf(client, "/dashboard")
    r = client.post("/note/new", data={"title": "Nota QA", "content": "ok", "csrf_token": token})
    assert r.status_code == 302
    assert "Nota QA" in client.get("/search?q=QA").get_data(as_text=True)


def test_rutas_protegidas_exigen_sesion(client):
    for path in ("/dashboard", "/search?q=a", "/ping", "/admin"):
        assert client.get(path).status_code == 302
