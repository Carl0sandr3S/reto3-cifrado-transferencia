"""Excepciones del dominio. Cada una lleva un código de salida estable.

Los códigos de salida permiten que un orquestador (Cloud Run Jobs, Control-M, Airflow)
distinga el tipo de fallo sin tener que leer los logs.
"""


class SecureTransferError(Exception):
    exit_code = 1


class ConfigError(SecureTransferError):
    """Configuración ausente o inválida (llave KMS mal formada, proveedor desconocido...)."""

    exit_code = 5


class KeyServiceError(SecureTransferError):
    """Fallo al envolver/desenvolver la llave de datos (KMS caído, sin permisos, llave incorrecta)."""

    exit_code = 5


class StorageError(SecureTransferError):
    """Fallo de lectura/escritura en GCS o en disco (no existe, sin permiso, ya existe)."""

    exit_code = 4


class CryptoError(SecureTransferError):
    exit_code = 3


class FormatError(CryptoError):
    """El archivo no tiene el formato esperado (cabecera corrupta, truncado, otra herramienta)."""


class IntegrityError(CryptoError):
    """La autenticación GCM o el SHA-256 no coinciden: el archivo fue alterado o está corrupto."""
