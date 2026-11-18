"""Genera el registro de trazabilidad de cada ejecucion del pipeline
(Generate Documentation). Une: commit -> build -> resultados de cada control.
Uso: python generate_traceability.py <carpeta_reports> <salida.md>"""
import datetime
import glob
import json
import os
import subprocess  # nosec B404
import sys
import xml.etree.ElementTree as ET  # nosec B405 - XML generado por el propio pipeline

reports, out = sys.argv[1], sys.argv[2]


def git(*args):
    try:
        return subprocess.check_output(["git", *args], text=True).strip()  # nosec
    except Exception:
        return os.environ.get("GIT_COMMIT", "n/d")


def junit():
    try:
        r = ET.parse(os.path.join(reports, "junit.xml")).getroot()
        s = r if r.tag == "testsuite" else r.find("testsuite")
        return f"{s.get('tests')} pruebas, {s.get('failures')} fallas, {s.get('errors')} errores"
    except Exception:
        return "sin reporte"


def bandit():
    try:
        m = json.load(open(os.path.join(reports, "bandit.json")))["metrics"]["_totals"]
        return f"High={m['SEVERITY.HIGH']} Medium={m['SEVERITY.MEDIUM']} Low={m['SEVERITY.LOW']}"
    except Exception:
        return "sin reporte"


def pip_audit():
    try:
        d = json.load(open(os.path.join(reports, "pip-audit.json")))
        deps = d["dependencies"] if isinstance(d, dict) else d
        vulns = sum(len(x.get("vulns", [])) for x in deps)
        return f"{len(deps)} dependencias analizadas, {vulns} vulnerabilidades conocidas"
    except Exception:
        return "sin reporte"


def zap():
    files = glob.glob(os.path.join(reports, "zap", "*.json"))
    if not files:
        return "sin reporte"
    counts = {}
    for site in json.load(open(files[0])).get("site", []):
        for a in site.get("alerts", []):
            risk = a.get("riskdesc", "?").split(" ")[0]
            counts[risk] = counts.get(risk, 0) + 1
    return ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "0 alertas"


now = datetime.datetime.now().isoformat(timespec="seconds")
rows = [
    ("Build Jenkins", f"#{os.environ.get('BUILD_NUMBER', 'local')} ({os.environ.get('BUILD_URL', '-')})"),
    ("Fecha", now),
    ("Commit", git("rev-parse", "HEAD")),
    ("Autor", git("log", "-1", "--format=%an <%ae>")),
    ("Mensaje", git("log", "-1", "--format=%s")),
    ("Rama", os.environ.get("BRANCH_NAME", git("rev-parse", "--abbrev-ref", "HEAD"))),
    ("Imagen Docker", os.environ.get("IMAGE", "n/d")),
    ("Pruebas (pytest)", junit()),
    ("SAST (Bandit)", bandit()),
    ("SCA (pip-audit)", pip_audit()),
    ("DAST (OWASP ZAP)", zap()),
]
with open(out, "w", encoding="utf-8") as f:
    f.write("# Registro de trazabilidad del pipeline\n\n| Campo | Valor |\n|---|---|\n")
    for k, v in rows:
        f.write(f"| {k} | {v} |\n")
    f.write("\n## Ultimos commits\n\n```\n" + git("log", "-10", "--format=%h %ad %an %s", "--date=short") + "\n```\n")
print(open(out, encoding="utf-8").read())
