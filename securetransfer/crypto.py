"""Formato de archivo cifrado y operaciones de cifrado/descifrado en streaming.

Formato (.enc):

    MAGIC (8 bytes "SECXFER1") | largo de cabecera (4 bytes, big-endian) | cabecera JSON | chunk_1 | ... | chunk_n

Cada chunk es AES-256-GCM (texto cifrado + tag de 16 bytes) con:
  - nonce de 12 bytes = prefijo aleatorio (7) || contador de chunk (4, big-endian) || bandera "último" (1)
  - AAD = MAGIC || largo || cabecera completa

Por qué este diseño (construcción tipo STREAM):
  * El contador en el nonce impide reordenar o duplicar chunks.
  * La bandera "último" impide truncar el archivo o añadirle chunks al final sin que se detecte.
  * La cabecera va como AAD: si alguien la modifica, TODOS los chunks dejan de autenticar.
  * El archivo se procesa por bloques (por defecto 1 MiB): memoria constante.
La cabecera incluye un bloque `meta` con el SHA-256 y el tamaño del original, CIFRADO con la propia DEK
(no en claro: un hash visible permitiría confirmar el contenido de archivos de baja entropía por fuerza
bruta, sin descifrar nada). Al descifrar se recalculan y se comparan, así la verificación "el archivo
recuperado es idéntico al original" es parte del propio flujo.
"""

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ConfigError, FormatError, IntegrityError
from .hashing import sha256_file
from .keys import KeyProvider

MAGIC = b"SECXFER1"
FORMAT_VERSION = 1
ALGORITHM = "AES-256-GCM-STREAM"
TAG_SIZE = 16
NONCE_PREFIX_SIZE = 7
KEY_SIZE = 32
MIN_CHUNK = 1024
MAX_CHUNK = 64 * 1024 * 1024
DEFAULT_CHUNK = 1024 * 1024
MAX_HEADER = 64 * 1024
KEY_CONTEXT = b"securetransfer/v1"  # AAD de KMS al envolver la DEK y del bloque `meta`
_META_COUNTER = b"\xff\xff\xff\xff"  # nonce del bloque meta: bandera 0x02, distinta de las de los chunks (0x00/0x01)
_LEN = struct.Struct(">I")


@dataclass(frozen=True)
class EncryptResult:
    sha256: str
    size: int
    encrypted_size: int
    chunk_size: int
    key_id: str


@dataclass(frozen=True)
class DecryptResult:
    sha256: str
    size: int
    verified: bool


# ----------------------------------------------------------------------------- helpers


def _nonce(prefix: bytes, counter: int, last: bool) -> bytes:
    if counter >= 2**32:
        raise ConfigError("Archivo demasiado grande para este tamaño de chunk; aumente --chunk-size")
    return prefix + counter.to_bytes(4, "big") + (b"\x01" if last else b"\x00")


def _meta_nonce(prefix: bytes) -> bytes:
    return prefix + _META_COUNTER + b"\x02"


def _read_full(fh: BinaryIO, n: int) -> bytes:
    """Lee exactamente n bytes salvo fin de archivo (read() puede devolver menos en algunos streams)."""
    parts: list[bytes] = []
    remaining = n
    while remaining:
        block = fh.read(remaining)
        if not block:
            break
        parts.append(block)
        remaining -= len(block)
    return b"".join(parts)


def _open_private(path: Path) -> BinaryIO:
    """Abre para escritura con permisos 0600: el texto en claro no debe ser legible por otros usuarios."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    return os.fdopen(fd, "wb")


def _check_chunk_size(chunk_size: int) -> None:
    if not MIN_CHUNK <= chunk_size <= MAX_CHUNK:
        raise ConfigError(f"chunk_size debe estar entre {MIN_CHUNK} y {MAX_CHUNK} bytes")


def _read_header(fh: BinaryIO) -> tuple[dict, bytes]:
    """Lee y valida la cabecera. Devuelve (cabecera, bytes_de_prefijo_usados_como_AAD)."""
    magic = _read_full(fh, len(MAGIC))
    if magic != MAGIC:
        raise FormatError("No es un archivo securetransfer (firma inválida)")
    raw_len = _read_full(fh, _LEN.size)
    if len(raw_len) != _LEN.size:
        raise FormatError("Archivo truncado: cabecera incompleta")
    (header_len,) = _LEN.unpack(raw_len)
    if not 0 < header_len <= MAX_HEADER:
        raise FormatError("Largo de cabecera inválido")
    header_bytes = _read_full(fh, header_len)
    if len(header_bytes) != header_len:
        raise FormatError("Archivo truncado: cabecera incompleta")
    try:
        header = json.loads(header_bytes)
        if header["v"] != FORMAT_VERSION or header["alg"] != ALGORITHM:
            raise FormatError(f"Versión o algoritmo no soportado: {header.get('v')}/{header.get('alg')}")
        chunk_size = int(header["chunk_size"])
        _check_chunk_size(chunk_size)
        prefix = base64.b64decode(header["nonce_prefix"], validate=True)
        wrapped = base64.b64decode(header["wrapped_dek"], validate=True)
        if len(prefix) != NONCE_PREFIX_SIZE or not wrapped:
            raise FormatError("Cabecera inconsistente")
        header["_chunk_size"], header["_prefix"], header["_wrapped"] = chunk_size, prefix, wrapped
        header["_meta"] = base64.b64decode(header["meta"], validate=True)
    except FormatError:
        raise
    except (ValueError, KeyError, TypeError) as exc:
        raise FormatError(f"Cabecera corrupta: {type(exc).__name__}") from exc
    return header, MAGIC + raw_len + header_bytes


# ----------------------------------------------------------------------------- API pública


def encrypt_file(src: str | Path, dst: str | Path, provider: KeyProvider, chunk_size: int = DEFAULT_CHUNK) -> EncryptResult:
    """Cifra src -> dst. Escribe a un .partial y lo renombra al final (nunca queda un .enc a medias)."""
    _check_chunk_size(chunk_size)
    src, dst = Path(src), Path(dst)

    plain_sha, plain_size = sha256_file(src)  # pasada 1: el hash va en la cabecera (autenticada)
    dek = os.urandom(KEY_SIZE)
    prefix = os.urandom(NONCE_PREFIX_SIZE)
    aead = AESGCM(dek)
    meta = aead.encrypt(_meta_nonce(prefix), json.dumps({"sha256": plain_sha, "size": plain_size}).encode(), KEY_CONTEXT)
    header = {
        "v": FORMAT_VERSION,
        "alg": ALGORITHM,
        "chunk_size": chunk_size,
        "nonce_prefix": base64.b64encode(prefix).decode(),
        "wrapped_dek": base64.b64encode(provider.wrap(dek, KEY_CONTEXT)).decode(),
        "key_id": provider.key_id,
        "meta": base64.b64encode(meta).decode(),
    }
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode()
    aad = MAGIC + _LEN.pack(len(header_bytes)) + header_bytes

    partial = dst.with_name(dst.name + ".partial")
    try:
        seen = 0
        with open(src, "rb") as fin, _open_private(partial) as fout:  # pasada 2: cifrado
            fout.write(aad)
            counter = 0
            buf = _read_full(fin, chunk_size)
            seen += len(buf)
            while True:
                nxt = _read_full(fin, chunk_size)  # lectura adelantada para saber cuál es el último chunk
                last = not nxt
                fout.write(aead.encrypt(_nonce(prefix, counter, last), buf, aad))
                if last:
                    break
                seen += len(nxt)
                buf, counter = nxt, counter + 1
        if seen != plain_size:
            raise IntegrityError("El archivo de origen cambió mientras se cifraba")
        os.replace(partial, dst)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise
    return EncryptResult(plain_sha, plain_size, dst.stat().st_size, chunk_size, provider.key_id)


def decrypt_file(src: str | Path, dst: str | Path, provider: KeyProvider) -> DecryptResult:
    """Descifra src -> dst y verifica tamaño y SHA-256 contra la cabecera autenticada.

    El texto en claro se escribe a un .partial (0600). Solo si TODO verifica se renombra a dst;
    ante cualquier fallo el .partial se elimina: nunca se entrega un archivo sin verificar.
    """
    src, dst = Path(src), Path(dst)
    partial = dst.with_name(dst.name + ".partial")
    with open(src, "rb") as fin:
        header, aad = _read_header(fin)
        chunk_size = header["_chunk_size"]
        prefix = header["_prefix"]
        dek = provider.unwrap(header["_wrapped"], KEY_CONTEXT)
        if len(dek) != KEY_SIZE:
            raise IntegrityError("DEK con largo inesperado")
        aead = AESGCM(dek)
        try:
            meta = json.loads(aead.decrypt(_meta_nonce(prefix), header["_meta"], KEY_CONTEXT))
            expected_sha, expected_size = meta["sha256"], int(meta["size"])
        except (InvalidTag, ValueError, KeyError, TypeError) as exc:
            raise IntegrityError("El bloque de metadatos no autentica: cabecera alterada o llave incorrecta") from exc
        hasher = hashlib.sha256()
        written = 0
        block = chunk_size + TAG_SIZE
        try:
            with _open_private(partial) as fout:
                counter = 0
                buf = _read_full(fin, block)
                while True:
                    if len(buf) < TAG_SIZE:
                        raise FormatError("Archivo truncado: chunk incompleto")
                    nxt = _read_full(fin, block)
                    last = not nxt
                    try:
                        plain = aead.decrypt(_nonce(prefix, counter, last), buf, aad)
                    except InvalidTag as exc:
                        raise IntegrityError(
                            f"Fallo de autenticación en el chunk {counter}: archivo alterado, truncado o corrupto"
                        ) from exc
                    hasher.update(plain)
                    fout.write(plain)
                    written += len(plain)
                    if last:
                        break
                    buf, counter = nxt, counter + 1
            if written != expected_size:
                raise IntegrityError("El tamaño descifrado no coincide con el declarado")
            digest = hasher.hexdigest()
            if digest != expected_sha:
                raise IntegrityError("El SHA-256 descifrado no coincide con el del original")
            os.replace(partial, dst)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
    return DecryptResult(digest, written, True)
