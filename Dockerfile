FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    SECXFER_LOG_FORMAT=json

# Usuario sin privilegios: si el contenedor se compromete, no corre como root.
RUN useradd --create-home --uid 10001 app
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY securetransfer ./securetransfer

USER 10001
ENTRYPOINT ["python", "-m", "securetransfer"]
CMD ["--help"]
