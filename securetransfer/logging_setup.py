"""Logging estructurado.

- Formato `json`: una línea JSON por evento con la clave `severity`, que Cloud Logging reconoce
  automáticamente (Cloud Run / Cloud Run Jobs), de modo que se puede filtrar por severidad, run_id, etc.
- Formato `text`: legible para desarrollo.

REGLA: no se loguean llaves, DEKs, contenido de archivos ni rutas con datos de clientes.
Solo se registran nombres de objeto, tamaños, hashes y duraciones.
"""

import json
import logging
import sys
import uuid

LOGGER_NAME = "securetransfer"


class _RunIdFilter(logging.Filter):
    def __init__(self, run_id: str):
        super().__init__()
        self.run_id = run_id

    def filter(self, record: logging.LogRecord) -> bool:
        record.run_id = self.run_id
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "run_id": getattr(record, "run_id", None),
            "logger": record.name,
        }
        payload.update(getattr(record, "fields", {}))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


class _TextFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        fields = " ".join(f"{k}={v}" for k, v in getattr(record, "fields", {}).items())
        base = f"{self.formatTime(record)} {record.levelname:<7} [{getattr(record, 'run_id', '-')}] {record.getMessage()}"
        text = f"{base} {fields}".rstrip()
        if record.exc_info:
            text += "\n" + self.formatException(record.exc_info)
        return text


def setup_logging(level: str = "INFO", fmt: str = "text") -> str:
    """Configura el logger de la app y devuelve el run_id de esta ejecución."""
    run_id = uuid.uuid4().hex[:12]
    logger = logging.getLogger(LOGGER_NAME)
    logger.handlers.clear()
    logger.setLevel(level.upper())
    logger.propagate = False
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter() if fmt == "json" else _TextFormatter())
    handler.addFilter(_RunIdFilter(run_id))
    logger.addHandler(handler)
    return run_id


def log_event(level: int, message: str, **fields) -> None:
    logging.getLogger(LOGGER_NAME).log(level, message, extra={"fields": fields})
