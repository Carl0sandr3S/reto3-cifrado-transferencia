"""Orquestación de los pasos del flujo. Cada función es una unidad reutilizable y testeable.

  send    (punto A)  origen -> [descargar] -> [cifrar con KMS] -> [subir] -> tránsito
  receive (punto B)  tránsito -> [descargar] -> [descifrar + verificar SHA-256] -> [subir] -> destino
  verify  (auditoría) compara el SHA-256 de dos archivos (original vs recuperado)

Todo el trabajo intermedio ocurre en un directorio temporal privado que se elimina siempre
(incluso si hay errores): el texto en claro nunca queda en disco al terminar.
"""

import logging
import tempfile
import time
from pathlib import Path

from . import storage
from .crypto import DEFAULT_CHUNK, decrypt_file, encrypt_file
from .hashing import sha256_file
from .keys import KeyProvider
from .logging_setup import log_event

ENC_SUFFIX = ".enc"


def send(source: str, destination: str, provider: KeyProvider, chunk_size: int = DEFAULT_CHUNK, overwrite: bool = False) -> dict:
    t0 = time.monotonic()
    dest = storage.resolve_destination(destination, source, add_suffix=ENC_SUFFIX)
    log_event(logging.INFO, "send: inicio", source=source, destination=dest, key_id=provider.key_id)
    with tempfile.TemporaryDirectory(prefix="secxfer-") as tmp:  # 0700, se borra al salir
        plain, enc = Path(tmp) / "plain", Path(tmp) / "cipher"
        storage.fetch(source, plain)
        res = encrypt_file(plain, enc, provider, chunk_size)
        log_event(logging.INFO, "send: cifrado", sha256=res.sha256, size=res.size, encrypted_size=res.encrypted_size)
        storage.put(enc, dest, overwrite)
    summary = {
        "operation": "send",
        "source": source,
        "destination": dest,
        "sha256": res.sha256,
        "size": res.size,
        "encrypted_size": res.encrypted_size,
        "key_id": res.key_id,
        "seconds": round(time.monotonic() - t0, 3),
    }
    log_event(logging.INFO, "send: completado", **summary)
    return summary


def receive(source: str, destination: str, provider: KeyProvider, overwrite: bool = False) -> dict:
    t0 = time.monotonic()
    dest = storage.resolve_destination(destination, source, strip_suffix=ENC_SUFFIX)
    log_event(logging.INFO, "receive: inicio", source=source, destination=dest)
    with tempfile.TemporaryDirectory(prefix="secxfer-") as tmp:
        enc, plain = Path(tmp) / "cipher", Path(tmp) / "plain"
        storage.fetch(source, enc)
        res = decrypt_file(enc, plain, provider)  # lanza IntegrityError si algo no cuadra
        log_event(logging.INFO, "receive: descifrado y verificado", sha256=res.sha256, size=res.size)
        storage.put(plain, dest, overwrite)
    summary = {
        "operation": "receive",
        "source": source,
        "destination": dest,
        "sha256": res.sha256,
        "size": res.size,
        "verified": res.verified,
        "seconds": round(time.monotonic() - t0, 3),
    }
    log_event(logging.INFO, "receive: completado", **summary)
    return summary


def verify(original: str, recovered: str) -> dict:
    """Compara dos archivos por SHA-256. `match` es la prueba de que el recuperado == original."""
    with tempfile.TemporaryDirectory(prefix="secxfer-") as tmp:
        a, b = Path(tmp) / "a", Path(tmp) / "b"
        storage.fetch(original, a)
        storage.fetch(recovered, b)
        (sha_a, size_a), (sha_b, size_b) = sha256_file(a), sha256_file(b)
    summary = {
        "operation": "verify",
        "original": original,
        "recovered": recovered,
        "sha256_original": sha_a,
        "sha256_recovered": sha_b,
        "size_original": size_a,
        "size_recovered": size_b,
        "match": sha_a == sha_b and size_a == size_b,
    }
    log_event(logging.INFO if summary["match"] else logging.ERROR, "verify: " + ("IDÉNTICOS" if summary["match"] else "DIFERENTES"), **summary)
    return summary
