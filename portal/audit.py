"""Auditoría en JSON por stdout (Cloud Run la envía a Cloud Logging).

Nunca se registra contenido de archivos, claves ni contraseñas: solo quién, qué, cuándo y el hash.
"""

import json
import logging
import time

log = logging.getLogger("portal")


def audit(event: str, **fields) -> None:
    """Registra un evento de auditoría como una línea JSON."""
    log.info(json.dumps({"event": event, "ts": int(time.time()), **fields}))
