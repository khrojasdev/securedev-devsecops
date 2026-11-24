"""
Sistema Academico - VERSION CORREGIDA (DevSecOps).

Corrige el codigo vulnerable entregado en la evaluacion (rama
baseline-vulnerable). Cada control indica el ID de la vulnerabilidad que
mitiga (VULN-XX) para la trazabilidad con el informe y docs/TRAZABILIDAD.md.
"""
import json
import logging
import os
import re
import secrets
import sqlite3
import sys
import time
from functools import wraps

from flask import (Flask, abort, g, redirect, render_template, request,
                   session, url_for)
from prometheus_client import (CONTENT_TYPE_LATEST, Counter, Histogram,
                               generate_latest)
from werkzeug.security import check_password_hash

app = Flask(__name__)

# VULN-07: la sesion ya no es una cookie con el nombre de usuario en texto
# plano. Se usa la sesion firmada de Flask; el secreto llega por variable de
# entorno (credencial de Jenkins). Sin variable, se genera uno aleatorio.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# VULN-08: cookie de sesion con HttpOnly, SameSite=Strict y Secure (con HTTPS)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=1800,
    MAX_CONTENT_LENGTH=64 * 1024,
)

MAX_BIO = 500
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 300
SUSPICIOUS_RE = re.compile(
    r"('|--|;|/\*|\bunion\b|\bor\b\s+\S+=|<script|onerror=|javascript:|\{\{|\{%)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# VULN-14: registro y monitoreo de eventos de seguridad (log JSON + Prometheus)
# ---------------------------------------------------------------------------
security_log = logging.getLogger("academico.security")
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("%(message)s"))
security_log.addHandler(_handler)
security_log.setLevel(logging.INFO)

HTTP_REQUESTS = Counter(
    "securedev_http_requests_total", "Peticiones HTTP", ["method", "endpoint", "status"]
)
HTTP_LATENCY = Histogram(
    "securedev_http_request_duration_seconds", "Latencia HTTP", ["endpoint"]
)
LOGIN_ATTEMPTS = Counter("securedev_login_attempts_total", "Intentos de login", ["result"])
SECURITY_EVENTS = Counter(
    "securedev_security_events_total", "Eventos de seguridad detectados", ["type"]
)


def security_event(event_type, **details):
    """Registra un evento de seguridad en log JSON y en Prometheus."""
    SECURITY_EVENTS.labels(type=event_type).inc()
    security_log.warning(json.dumps({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "event": event_type,
        "ip": request.remote_addr,
        "user": session.get("username"),
        "path": request.path,
        **details,
    }))


def flag_suspicious(value, field):
    """Deteccion (no defensa): marca entradas con patrones de SQLi/XSS/SSTI."""
    if value and SUSPICIOUS_RE.search(value):
        security_event("suspicious_input", field=field, sample=value[:80])


# ---------------------------------------------------------------------------
# Base de datos
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(os.environ.get("DB_PATH", "academico.db"))
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
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


def csrf_token():
    """VULN-06: token anti-CSRF sincronizado por sesion."""
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def before():
    g.start = time.perf_counter()
    # VULN-07: la cookie insegura de la version original ya no da acceso;
    # si alguien la envia (sesion falsificada) se registra el intento.
    if "user_session" in request.cookies:
        security_event("session_forgery", value=request.cookies["user_session"][:40])
    # Cookie de sesion presente pero con firma invalida (manipulada)
    if request.cookies.get(app.config["SESSION_COOKIE_NAME"]) and not session:
        security_event("session_forgery", reason="firma invalida")
    # VULN-06: todo POST exige el token anti-CSRF
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        expected = session.get("_csrf", "")
        if not expected or not secrets.compare_digest(sent, expected):
            security_event("csrf_rejected")
            abort(400)


@app.after_request
def security_headers(resp):
    # VULN-12: cabeceras de seguridad (OWASP Secure Headers)
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


# VULN-12: paginas de error genericas (sin trazas ni SQL)
@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, msg="Solicitud inválida"), 400


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="No encontrado"), 404


@app.errorhandler(413)
def too_large(_e):
    return render_template("error.html", code=413, msg="Solicitud demasiado grande"), 413


@app.errorhandler(500)
def server_error(_e):
    return render_template("error.html", code=500, msg="Error interno"), 500


# ---------------------------------------------------------------------------
# Rutas (mismas funcionalidades que el codigo original)
# ---------------------------------------------------------------------------
_failed_logins = {}


@app.route("/")
def home():
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

        # VULN-11: bloqueo temporal tras 5 intentos fallidos (por IP + usuario)
        key = f"{ip}|{username}"
        fails, since = _failed_logins.get(key, (0, time.time()))
        if fails >= MAX_FAILED_LOGINS and time.time() - since < LOCKOUT_SECONDS:
            LOGIN_ATTEMPTS.labels(result="locked").inc()
            security_event("bruteforce_lockout", username=username)
            return render_template("login.html", error="Cuenta bloqueada temporalmente"), 429

        # VULN-01: consulta parametrizada (el dato nunca se interpreta como SQL)
        user = get_db().execute(
            "SELECT * FROM usuarios WHERE username = ?", (username,)
        ).fetchone()
        # VULN-09: la contrasena se compara contra un hash scrypt con sal
        if user and check_password_hash(user["password"], password):
            _failed_logins.pop(key, None)
            session.clear()  # evita fijacion de sesion
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            LOGIN_ATTEMPTS.labels(result="success").inc()
            security_log.info(json.dumps({"event": "login_success", "user": username, "ip": ip}))
            return redirect(url_for("dashboard"))

        _failed_logins[key] = (fails + 1, since if fails else time.time())
        LOGIN_ATTEMPTS.labels(result="failure").inc()
        security_event("login_failure", username=username)
        error = "Credenciales inválidas"  # mensaje generico
        return render_template("login.html", error=error), 401
    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    # VULN-02: el usuario sale de la sesion firmada y la consulta es parametrizada
    datos = get_db().execute(
        "SELECT username, rol, bio FROM usuarios WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if datos is None:
        session.clear()
        return redirect(url_for("login"))
    # VULN-04 / VULN-05: plantilla fija con autoescape; la biografia es un dato,
    # nunca parte del codigo de la plantilla
    return render_template("dashboard.html", datos=datos)


@app.route("/update_bio", methods=["POST"])
@login_required
def update_bio():
    nueva_bio = request.form.get("nueva_bio", "").strip()
    if len(nueva_bio) > MAX_BIO:
        abort(400)
    flag_suspicious(nueva_bio, "nueva_bio")
    # VULN-03: UPDATE parametrizado: ya no se puede cambiar el rol ni otros usuarios
    db = get_db()
    db.execute("UPDATE usuarios SET bio = ? WHERE id = ?", (nueva_bio, session["user_id"]))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    # VULN-12: sin modo depuracion; en produccion se usa gunicorn (Dockerfile)
    app.run(host="127.0.0.1", port=5000)
