#!/bin/sh
set -e
# Inicializa la BD solo la primera vez
if [ ! -f "$DB_PATH" ]; then
  python -c "import app; app.init_db()"
fi
exec gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 \
     --access-logfile - --error-logfile - app:app
