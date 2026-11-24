#!/bin/sh
set -e
# La BD vive en /data (volumen). El codigo original crea vulnerable.db en el
# directorio actual; la version corregida usa DB_PATH (/data/academico.db).
cd /data
if [ ! -f /data/academico.db ] && [ ! -f /data/vulnerable.db ]; then
  python /app/init_db.py
fi
exec gunicorn --chdir /data --pythonpath /app --bind 0.0.0.0:5000 --workers 1 --threads 4 \
     --access-logfile - --error-logfile - app:app
