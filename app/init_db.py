"""Crea la base de datos del Sistema Academico - VERSION CORREGIDA.

VULN-09: las contrasenas se guardan con hash scrypt + sal (nunca en texto plano).
VULN-10: no hay credenciales por defecto. Las claves llegan por variables de
entorno (ADMIN_PASSWORD, ALUMNO_PASSWORD); si faltan o tienen menos de 12
caracteres se genera una clave aleatoria que no se muestra.
"""
import os
import secrets
import sqlite3

from werkzeug.security import generate_password_hash

MIN_LEN = 12


def _password(var):
    pw = os.environ.get(var, "")
    return pw if len(pw) >= MIN_LEN else secrets.token_urlsafe(18)


def crear_base_de_datos(path=None):
    path = path or os.environ.get("DB_PATH", "academico.db")
    conexion = sqlite3.connect(path)
    cursor = conexion.cursor()

    cursor.execute("DROP TABLE IF EXISTS usuarios")
    cursor.execute(
        """
        CREATE TABLE usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            rol TEXT NOT NULL,
            bio TEXT
        )
        """
    )
    usuarios = [
        ("admin", generate_password_hash(_password("ADMIN_PASSWORD")), "admin",
         "Cuenta de administrador del sistema."),
        ("alumno", generate_password_hash(_password("ALUMNO_PASSWORD")), "user",
         "Soy un estudiante aprendiendo hacking."),
    ]
    cursor.executemany(
        "INSERT INTO usuarios (username, password, rol, bio) VALUES (?, ?, ?, ?)", usuarios
    )
    conexion.commit()
    conexion.close()
    print("Base de datos inicializada (contraseñas con hash).")


if __name__ == "__main__":
    crear_base_de_datos()
