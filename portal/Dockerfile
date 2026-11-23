# Imagen del PORTAL (distinta de la de los jobs: el portal no lleva el código de cifrado ni dependencias de KMS).
# Contexto de construcción: la carpeta portal/ (ver deploy/portal.py). El código queda como paquete `portal`.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN useradd --create-home --uid 10001 app
WORKDIR /srv

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . ./portal

USER 10001
# Cloud Run inyecta PORT. Un solo proceso con hilos: el estado del flujo en curso vive en el proceso.
CMD exec gunicorn --bind :${PORT:-8080} --workers 1 --threads 8 --timeout 120 "portal.app:create_app()"
