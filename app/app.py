"""
SecureDev Notes - VERSION VULNERABLE (linea base de la auditoria).

!! NO USAR EN PRODUCCION !!
Este codigo contiene vulnerabilidades intencionales para la Evaluacion
Parcial N°3 de OCY1102. Cada una esta marcada con su ID (VULN-XX).
"""
import base64
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import (Flask, g, redirect, render_template, render_template_string,
                   request, session)

app = Flask(__name__)
app.secret_key = "securedev123"  # VULN-08: secreto hardcodeado en el codigo
app.config["DB_PATH"] = os.environ.get("DB_PATH", "securedev.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(app.config["DB_PATH"])
    db.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS notes;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, role TEXT, email TEXT);
        CREATE TABLE notes (id INTEGER PRIMARY KEY, owner_id INTEGER,
                            title TEXT, content TEXT);
        """
    )
    # VULN-09: contrasenas guardadas en texto plano
    db.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
        [
            ("admin", "admin123", "admin", "admin@securedev.cl"),
            ("kevin", "kevin2024", "user", "kevin@securedev.cl"),
            ("ana", "ana2024", "user", "ana@securedev.cl"),
        ],
    )
    db.executemany(
        "INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
        [
            (1, "Credenciales servidor", "root / P@ssw0rd-prod"),
            (2, "Pendientes", "Terminar informe EVA3"),
            (3, "Privado de Ana", "Datos personales de Ana"),
        ],
    )
    db.commit()
    db.close()


@app.route("/")
def index():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN-01: SQL Injection (concatenacion de entrada del usuario)
        query = (
            f"SELECT * FROM users WHERE username = '{username}' "
            f"AND password = '{password}'"
        )
        try:
            user = get_db().execute(query).fetchone()
        except Exception as exc:  # VULN-12: divulgacion de errores internos
            return f"Error de base de datos: {exc} <br>Consulta: {query}", 500
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            return redirect("/dashboard")
        error = "Credenciales invalidas"  # VULN-14: sin limite de intentos (fuerza bruta)
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    notes = get_db().execute(
        f"SELECT * FROM notes WHERE owner_id = {session['user_id']}"
    ).fetchall()
    return render_template("dashboard.html", notes=notes)


@app.route("/search")
def search():
    if "user_id" not in session:
        return redirect("/login")
    q = request.args.get("q", "")
    # VULN-01: SQL Injection en busqueda
    rows = get_db().execute(
        f"SELECT * FROM notes WHERE owner_id = {session['user_id']} "
        f"AND title LIKE '%{q}%'"
    ).fetchall()
    # VULN-02 / VULN-03: XSS reflejado + SSTI (entrada concatenada a la plantilla)
    template = (
        "{% extends 'base.html' %}{% block content %}"
        "<h2>Resultados para: " + q + "</h2><ul>"
        "{% for r in rows %}<li>{{ r['title'] }}</li>{% endfor %}"
        "</ul>{% endblock %}"
    )
    return render_template_string(template, rows=rows)


@app.route("/note/new", methods=["POST"])
def new_note():
    # VULN-07: sin token anti-CSRF
    if "user_id" not in session:
        return redirect("/login")
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
        (session["user_id"], request.form["title"], request.form["content"]),
    )
    db.commit()
    return redirect("/dashboard")


@app.route("/note/<int:note_id>")
def view_note(note_id):
    if "user_id" not in session:
        return redirect("/login")
    # VULN-05: IDOR - no se valida que la nota pertenezca al usuario
    note = get_db().execute(
        "SELECT * FROM notes WHERE id = ?", (note_id,)
    ).fetchone()
    if not note:
        return "No existe", 404
    # VULN-02: XSS almacenado (la plantilla usa |safe)
    return render_template("note.html", note=note)


@app.route("/ping")
def ping():
    if "user_id" not in session:
        return redirect("/login")
    host = request.args.get("host", "127.0.0.1")
    # VULN-04: inyeccion de comandos del sistema operativo (shell=True)
    try:
        output = subprocess.check_output(
            f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=10
        ).decode()
    except subprocess.CalledProcessError as exc:
        output = exc.output.decode()
    return render_template("ping.html", host=host, output=output)


@app.route("/admin")
def admin():
    # VULN-06: control de acceso roto - solo valida sesion, no el rol
    if "user_id" not in session:
        return redirect("/login")
    users = get_db().execute("SELECT * FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/import", methods=["POST"])
def import_notes():
    if "user_id" not in session:
        return redirect("/login")
    # VULN-10: deserializacion insegura (pickle sobre datos del usuario)
    data = pickle.loads(base64.b64decode(request.form["data"]))
    return {"importadas": len(data)}


@app.route("/fetch")
def fetch():
    if "user_id" not in session:
        return redirect("/login")
    # VULN-11: SSRF - el servidor descarga cualquier URL indicada
    url = request.args.get("url", "")
    resp = requests.get(url, timeout=5)
    return resp.text[:2000]


if __name__ == "__main__":
    init_db()
    # VULN-12: modo debug activo y expuesto en todas las interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
