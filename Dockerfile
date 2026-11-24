# syntax=docker/dockerfile:1
# Imagen multi-etapa: "test" (pruebas + SAST + SCA) y "runtime" (produccion).
FROM python:3.13-slim AS base
# Repositorios apt por HTTPS (algunas redes bloquean HTTP plano)
RUN sed -i 's#http://deb.debian.org#https://deb.debian.org#g' /etc/apt/sources.list.d/debian.sources
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --create-home --uid 10001 appuser
WORKDIR /app
COPY app/requirements.txt .
RUN pip install -r requirements.txt

# ---------- Etapa de pruebas (usada por Jenkins) ----------
FROM base AS test
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* && git config --system --add safe.directory '*'
COPY app/requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY app/ /app/
COPY scripts/ /scripts/
RUN mkdir -p /reports
CMD ["pytest", "-q"]

# ---------- Etapa de ejecucion (produccion) ----------
FROM base AS runtime
# Codigo de solo lectura para appuser (propiedad de root); sin las pruebas
COPY app/ /app/
RUN rm -rf /app/tests /app/requirements-dev.txt
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod 0555 /entrypoint.sh && mkdir -p /data && chown appuser:appuser /data
ENV DB_PATH=/data/academico.db
# Principio de minimo privilegio: el contenedor no corre como root
USER appuser
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/health',timeout=2)"
ENTRYPOINT ["/entrypoint.sh"]
