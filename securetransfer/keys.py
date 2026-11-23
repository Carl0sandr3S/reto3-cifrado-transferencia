"""Proveedores de llaves (envelope encryption).

El archivo se cifra con una llave de datos (DEK) aleatoria de 256 bits que se genera por cada
archivo. La DEK nunca se guarda en claro: se "envuelve" (cifra) con una llave maestra (KEK) que
vive en Cloud KMS y nunca sale de allí. La DEK envuelta viaja dentro de la cabecera del archivo.

  - KmsKeyProvider   -> producción. La KEK está en Cloud KMS.
  - LocalKeyProvider -> SOLO desarrollo y pruebas. La KEK sale de una variable de entorno.
"""

import base64
import binascii
import os
import re
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ConfigError, KeyServiceError


class KeyProvider(Protocol):
    key_id: str

    def wrap(self, dek: bytes, context: bytes) -> bytes: ...

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes: ...


_KMS_KEY_RE = re.compile(r"^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$")


class KmsKeyProvider:
    """Envuelve/desenvuelve la DEK con Cloud KMS.

    Se usa el nombre de la CryptoKey (sin versión): KMS cifra con la versión primaria y, al
    descifrar, elige solo la versión correcta. Por eso rotar la llave no rompe archivos viejos.
    El `context` viaja como additional_authenticated_data: KMS rechaza el descifrado si no coincide.
    """

    def __init__(self, key_name: str, client=None):
        if not _KMS_KEY_RE.match(key_name or ""):
            raise ConfigError(
                "SECXFER_KMS_KEY inválida. Formato esperado: "
                "projects/<proyecto>/locations/<región>/keyRings/<anillo>/cryptoKeys/<llave>"
            )
        self.key_id = key_name
        if client is None:
            try:
                from google.cloud import kms  # import perezoso: no es necesario en pruebas
            except ImportError as exc:
                raise ConfigError("Falta la dependencia google-cloud-kms") from exc
            client = kms.KeyManagementServiceClient()
        self._client = client

    def wrap(self, dek: bytes, context: bytes) -> bytes:
        try:
            resp = self._client.encrypt(
                request={"name": self.key_id, "plaintext": dek, "additional_authenticated_data": context}
            )
        except Exception as exc:  # frontera con la API externa: se traduce a un error de dominio
            raise KeyServiceError(f"KMS encrypt falló ({type(exc).__name__}): {exc}") from exc
        return resp.ciphertext

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        try:
            resp = self._client.decrypt(
                request={"name": self.key_id, "ciphertext": wrapped, "additional_authenticated_data": context}
            )
        except Exception as exc:
            raise KeyServiceError(f"KMS decrypt falló ({type(exc).__name__}): {exc}") from exc
        return resp.plaintext


class LocalKeyProvider:
    """KEK local en memoria. NO USAR EN PRODUCCIÓN: la llave maestra no está protegida por un HSM/KMS."""

    key_id = "local-dev"

    def __init__(self, master_key_b64: str):
        try:
            key = base64.b64decode(master_key_b64, validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ConfigError("SECXFER_LOCAL_KEY no es base64 válido") from exc
        if len(key) != 32:
            raise ConfigError("SECXFER_LOCAL_KEY debe decodificar a exactamente 32 bytes")
        self._aead = AESGCM(key)

    def wrap(self, dek: bytes, context: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + self._aead.encrypt(nonce, dek, context)

    def unwrap(self, wrapped: bytes, context: bytes) -> bytes:
        try:
            return self._aead.decrypt(wrapped[:12], wrapped[12:], context)
        except InvalidTag as exc:
            raise KeyServiceError("No se pudo desenvolver la DEK: llave incorrecta o cabecera alterada") from exc


def generate_local_key() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def build_provider(name: str, kms_key: str | None, local_key: str | None) -> KeyProvider:
    if name == "kms":
        return KmsKeyProvider(kms_key or "")
    if name == "local":
        if not local_key:
            raise ConfigError("Con --key-provider local se requiere SECXFER_LOCAL_KEY")
        return LocalKeyProvider(local_key)
    raise ConfigError(f"Proveedor de llaves desconocido: {name!r} (use 'kms' o 'local')")
