"""
SecureDev Notes - VERSION CORREGIDA (DevSecOps).

Cada control de seguridad referencia el ID de la vulnerabilidad que mitiga
(VULN-XX) para mantener la trazabilidad con el informe y la matriz de
trazabilidad (docs/TRAZABILIDAD.md).
"""
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import shutil
import subprocess  # nosec B404 - uso controlado: lista de argumentos, sin shell
import sys
import time
from functools import wraps
from urllib.parse import urlparse

import requests
from flask import (Flask, abort, g, redirect, render_template, request,
                   session, url_for)
from prometheus_client import (CONTENT_TYPE_LATEST, Counter, Histogram,
                               generate_latest)
from werkzeug.security import check_password_hash, generate_password_hash

# ---------------------------------------------------------------------------
# Configuracion segura
# ---------------------------------------------------------------------------
app = Flask(__name__)

# VULN-08: el secreto se lee desde variable de entorno (Jenkins credentials /
# Docker secret). Si no existe se genera uno aleatorio por arranque.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    DB_PATH=os.environ.get("DB_PATH", "securedev.db"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    # En produccion detras de HTTPS se activa con COOKIE_SECURE=1
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=1 * 1024 * 1024,
)

MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
FETCH_ALLOWED_HOSTS = {"api.github.com", "pypi.org"}
PING_BIN = shutil.which("ping") or "/bin/ping"  # ruta absoluta (B607)
HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-zA-Z0-9-]{1,63}\.)*[a-zA-Z0-9-]{1,63}$")
SUSPICIOUS_RE = re.compile(
    r"('|--|;|/\*|\bunion\b|\bor\b\s+\d|<script|onerror=|\{\{|\{%|\$\(|`|\|)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Logging de seguridad (JSON a stdout -> recolectado por Docker / Grafana)
# ---------------------------------------------------------------------------
security_log = logging.getLogger("securedev.security")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
security_log.addHandler(_handler)
security_log.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Metricas Prometheus (consumidas por Grafana)
# ---------------------------------------------------------------------------
HTTP_REQUESTS = Counter(
    "securedev_http_requests_total", "Peticiones HTTP", ["method", "endpoint", "status"]
)
HTTP_LATENCY = Histogram(
    "securedev_http_request_duration_seconds", "Latencia HTTP", ["endpoint"]
)
LOGIN_ATTEMPTS = Counter(
    "securedev_login_attempts_total", "Intentos de login", ["result"]
)
SECURITY_EVENTS = Counter(
    "securedev_security_events_total", "Eventos de seguridad detectados", ["type"]
)


def security_event(event_type, **details):
    """Registra un evento de seguridad en log JSON y en Prometheus."""
    SECURITY_EVENTS.labels(type=event_type).inc()
    security_log.warning(
        json.dumps(
            {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "event": event_type,
                "ip": request.remote_addr if request else None,
                "user": session.get("username") if request else None,
                "path": request.path if request else None,
                **details,
            }
        )
    )


def flag_suspicious(value, field):
    """Deteccion (no defensa): marca entradas con patrones de ataque."""
    if value and SUSPICIOUS_RE.search(value):
        security_event("suspicious_input", field=field, sample=value[:80])


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
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
    # VULN-09: contrasenas con hash robusto (scrypt + sal) en vez de texto plano
    seed_pw = {
        "admin": os.environ.get("ADMIN_PASSWORD", "Adm1n!SecureDev-2026"),
        "kevin": os.environ.get("KEVIN_PASSWORD", "Kev1n!SecureDev-2026"),
        "ana": os.environ.get("ANA_PASSWORD", "An4!SecureDev-2026"),
    }
    db.executemany(
        "INSERT INTO users (username, password, role, email) VALUES (?,?,?,?)",
        [
            ("admin", generate_password_hash(seed_pw["admin"]), "admin", "admin@securedev.cl"),
            ("kevin", generate_password_hash(seed_pw["kevin"]), "user", "kevin@securedev.cl"),
            ("ana", generate_password_hash(seed_pw["ana"]), "user", "ana@securedev.cl"),
        ],
    )
    db.executemany(
        "INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
        [
            (1, "Checklist de despliegue", "Rotar credenciales en el gestor de secretos"),
            (2, "Pendientes", "Terminar informe EVA3"),
            (3, "Privado de Ana", "Datos personales de Ana"),
        ],
    )
    db.commit()
    db.close()


# ---------------------------------------------------------------------------
# Controles transversales
# ---------------------------------------------------------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def role_required(role):
    """VULN-06: autorizacion basada en roles (RBAC)."""

    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("role") != role:
                security_event("access_denied", required_role=role)
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def csrf_token():
    """VULN-07: token anti-CSRF sincronizado por sesion."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def before():
    g.start = time.perf_counter()
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            security_event("csrf_rejected")
            abort(400)


@app.after_request
def security_headers(resp):
    # Cabeceras recomendadas por OWASP ZAP / OWASP Secure Headers
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
    )
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    endpoint = request.url_rule.rule if request.url_rule else "unmatched"
    HTTP_REQUESTS.labels(request.method, endpoint, resp.status_code).inc()
    if hasattr(g, "start"):
        HTTP_LATENCY.labels(endpoint).observe(time.perf_counter() - g.start)
    return resp


# VULN-12: manejadores de error genericos (sin trazas ni consultas SQL)
@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, msg="Solicitud inválida"), 400


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="Acceso denegado"), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="No encontrado"), 404


@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500, msg="Error interno"), 500


# ---------------------------------------------------------------------------
# Rutas
# ---------------------------------------------------------------------------
_failed_logins = {}


@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))


@app.route("/health")
def health():
    return {"status": "ok"}


@app.route("/metrics")
def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "unknown"
        username = request.form.get("username", "")[:64]
        password = request.form.get("password", "")[:128]
        flag_suspicious(username, "username")

        # VULN-14: bloqueo temporal ante fuerza bruta (por IP + usuario)
        key = f"{ip}|{username}"
        fails, since = _failed_logins.get(key, (0, time.time()))
        if fails >= MAX_FAILED_LOGINS and time.time() - since < LOCKOUT_SECONDS:
            LOGIN_ATTEMPTS.labels(result="locked").inc()
            security_event("bruteforce_lockout", username=username)
            return render_template("login.html", error="Cuenta bloqueada temporalmente"), 429

        # VULN-01: consulta parametrizada
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password"], password):
            _failed_logins.pop(key, None)
            session.clear()  # evita fijacion de sesion
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            LOGIN_ATTEMPTS.labels(result="success").inc()
            security_log.info(json.dumps({"event": "login_success", "user": username, "ip": ip}))
            return redirect(url_for("dashboard"))

        _failed_logins[key] = (fails + 1, since if fails else time.time())
        LOGIN_ATTEMPTS.labels(result="failure").inc()
        security_event("login_failure", username=username)
        error = "Credenciales inválidas"  # mensaje generico
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    notes = get_db().execute(
        "SELECT * FROM notes WHERE owner_id = ?", (session["user_id"],)
    ).fetchall()
    return render_template("dashboard.html", notes=notes)


@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "")[:100]
    flag_suspicious(q, "q")
    # VULN-01: parametrizado | VULN-02/03: la entrada se pasa como dato a una
    # plantilla estatica con autoescape (no se concatena a la plantilla)
    rows = get_db().execute(
        "SELECT * FROM notes WHERE owner_id = ? AND title LIKE ?",
        (session["user_id"], f"%{q}%"),
    ).fetchall()
    return render_template("search.html", q=q, rows=rows)


@app.route("/note/new", methods=["POST"])
@login_required
def new_note():
    title = request.form.get("title", "").strip()[:120]
    content = request.form.get("content", "").strip()[:5000]
    if not title:
        abort(400)
    flag_suspicious(content, "content")
    db = get_db()
    db.execute(
        "INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
        (session["user_id"], title, content),
    )
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/note/<int:note_id>")
@login_required
def view_note(note_id):
    # VULN-05: se valida la propiedad del recurso (o rol admin)
    note = get_db().execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    if not note or (note["owner_id"] != session["user_id"] and session.get("role") != "admin"):
        if note:
            security_event("idor_attempt", note_id=note_id)
        abort(404)
    return render_template("note.html", note=note)


def _valid_host(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_RE.match(host))


@app.route("/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1").strip()
    # VULN-04: validacion estricta (lista blanca) y sin shell
    if not _valid_host(host):
        security_event("command_injection_blocked", sample=host[:80])
        abort(400)
    try:
        result = subprocess.run(  # nosec B603 - argumentos validados, sin shell
            [PING_BIN, "-c", "1", "-W", "2", host],
            capture_output=True, text=True, timeout=5, check=False,
        )
        output = result.stdout or result.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        output = "No fue posible ejecutar el diagnóstico"
    return render_template("ping.html", host=host, output=output)


@app.route("/admin")
@role_required("admin")
def admin():
    # VULN-06 / VULN-09: solo admin, y nunca se exponen hashes
    users = get_db().execute("SELECT id, username, role, email FROM users").fetchall()
    return render_template("admin.html", users=users)


@app.route("/import", methods=["POST"])
@login_required
def import_notes():
    # VULN-10: JSON con validacion de esquema en vez de pickle
    try:
        data = json.loads(request.form.get("data", ""))
    except (ValueError, TypeError):
        security_event("deserialization_rejected")
        abort(400)
    if not isinstance(data, list) or len(data) > 100 or not all(
        isinstance(n, dict) and isinstance(n.get("title"), str) and isinstance(n.get("content", ""), str)
        for n in data
    ):
        abort(400)
    db = get_db()
    db.executemany(
        "INSERT INTO notes (owner_id, title, content) VALUES (?,?,?)",
        [(session["user_id"], n["title"][:120], n.get("content", "")[:5000]) for n in data],
    )
    db.commit()
    return {"importadas": len(data)}


@app.route("/fetch")
@login_required
def fetch():
    # VULN-11: lista blanca de destinos, solo HTTPS, sin redirecciones
    url = request.args.get("url", "")
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in FETCH_ALLOWED_HOSTS:
        security_event("ssrf_blocked", sample=url[:120])
        abort(400)
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return {"status": resp.status_code, "length": len(resp.content)}


if __name__ == "__main__":
    if not os.path.exists(app.config["DB_PATH"]):
        init_db()
    # VULN-12: debug desactivado; en produccion se usa gunicorn (Dockerfile)
    app.run(host="127.0.0.1", port=5000, debug=False)
