"""CLI. Toda la configuración llega por argumentos o variables de entorno: nada está hardcodeado.

Códigos de salida: 0 ok | 1 inesperado | 2 uso incorrecto | 3 cripto/integridad | 4 almacenamiento
                   5 configuración/llaves | 6 verify: los archivos NO coinciden
"""

import argparse
import json
import logging
import os
import sys

from . import __version__, pipeline
from .crypto import DEFAULT_CHUNK
from .errors import SecureTransferError
from .keys import build_provider, generate_local_key
from .logging_setup import log_event, setup_logging

EXIT_MISMATCH = 6


def _env(name: str, default=None):
    return os.environ.get(name, default)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="securetransfer", description="Cifrado (envelope, Cloud KMS) y transferencia de archivos.")
    p.add_argument("--version", action="version", version=__version__)
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--log-level", default=_env("SECXFER_LOG_LEVEL", "INFO"), choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    common.add_argument("--log-format", default=_env("SECXFER_LOG_FORMAT", "text"), choices=["text", "json"])

    keys = argparse.ArgumentParser(add_help=False)
    keys.add_argument("--key-provider", default=_env("SECXFER_KEY_PROVIDER", "kms"), choices=["kms", "local"],
                      help="kms (producción) o local (solo pruebas). Env: SECXFER_KEY_PROVIDER")
    keys.add_argument("--kms-key", default=_env("SECXFER_KMS_KEY"),
                      help="projects/P/locations/L/keyRings/R/cryptoKeys/K. Env: SECXFER_KMS_KEY")
    keys.add_argument("--chunk-size", type=int, default=int(_env("SECXFER_CHUNK_SIZE", DEFAULT_CHUNK)),
                      help="Bytes por chunk (1 KiB - 64 MiB). Env: SECXFER_CHUNK_SIZE")

    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("send", parents=[common, keys], help="Punto A: cifra el origen y lo deja en tránsito")
    s.add_argument("--source", required=True, help="Archivo origen (ruta o gs://...)")
    s.add_argument("--destination", required=True, help="Destino cifrado (ruta/gs://...; si termina en '/' se usa <nombre>.enc)")
    s.add_argument("--overwrite", action="store_true")

    r = sub.add_parser("receive", parents=[common, keys], help="Punto B: descifra, verifica y entrega el original")
    r.add_argument("--source", required=True, help="Archivo cifrado (ruta o gs://...)")
    r.add_argument("--destination", required=True, help="Destino del original recuperado (si termina en '/' se quita .enc)")
    r.add_argument("--overwrite", action="store_true")

    v = sub.add_parser("verify", parents=[common], help="Compara SHA-256 del original contra el recuperado")
    v.add_argument("--original", required=True)
    v.add_argument("--recovered", required=True)

    sub.add_parser("gen-local-key", help="Genera una llave aleatoria para --key-provider local (solo pruebas)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "gen-local-key":
        print(generate_local_key())
        return 0

    run_id = setup_logging(args.log_level, args.log_format)
    try:
        if args.command == "verify":
            result = pipeline.verify(args.original, args.recovered)
            print(json.dumps(result))
            return 0 if result["match"] else EXIT_MISMATCH

        provider = build_provider(args.key_provider, args.kms_key, _env("SECXFER_LOCAL_KEY"))
        if args.key_provider == "local":
            log_event(logging.WARNING, "Proveedor de llaves LOCAL: solo para pruebas, no usar con datos reales")
        if args.command == "send":
            result = pipeline.send(args.source, args.destination, provider, args.chunk_size, args.overwrite)
        else:
            result = pipeline.receive(args.source, args.destination, provider, args.overwrite)
        print(json.dumps(result))
        return 0
    except SecureTransferError as exc:
        # Error esperado: se registra el mensaje (sin traceback) y se devuelve un código estable.
        log_event(logging.ERROR, f"{type(exc).__name__}: {exc}", run_id=run_id, exit_code=exc.exit_code)
        return exc.exit_code
    except KeyboardInterrupt:
        log_event(logging.ERROR, "Interrumpido por el usuario")
        return 130
    except Exception:  # noqa: BLE001 - última red de seguridad: se registra con traceback
        logging.getLogger("securetransfer").exception("Error inesperado")
        return 1


if __name__ == "__main__":
    sys.exit(main())
