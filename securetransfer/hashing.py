"""Utilidades de hash. SHA-256 en streaming: no carga el archivo completo en memoria."""

import hashlib
from pathlib import Path

_BLOCK = 1024 * 1024


def sha256_file(path: str | Path) -> tuple[str, int]:
    """Devuelve (sha256_hex, tamaño_en_bytes) del archivo."""
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        while block := fh.read(_BLOCK):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size
