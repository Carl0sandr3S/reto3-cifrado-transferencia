"""Abstracción de almacenamiento: rutas locales o URIs gs://bucket/objeto.

Mismo código para desarrollo (disco) y producción (GCS). Las dependencias de Google se importan
de forma perezosa, así las pruebas locales no las necesitan.

Restricción de carpeta (medallion): si la variable de entorno SECXFER_ALLOWED_PREFIX está definida (los Cloud Run
Jobs la reciben con el valor "portal/"), las URIs gs:// solo pueden apuntar a objetos que empiecen por ese prefijo.
Es una segunda barrera además de las condiciones de IAM: aunque alguien pase otra ruta por argumentos, el job se niega.
No afecta a las rutas locales (desarrollo).

Escritura "sin sobrescribir" por defecto:
  - GCS: `if_generation_match=0` (la subida falla si el objeto ya existe). Además permite que la
    cuenta de servicio solo tenga `roles/storage.objectCreator` (puede crear, no pisar ni borrar).
  - Disco: se comprueba que no exista y se escribe con un archivo temporal + rename atómico.
"""

import os
import shutil
from pathlib import Path
from urllib.parse import urlparse

from .errors import StorageError


def is_gcs(uri: str) -> bool:
    return str(uri).startswith("gs://")


def parse_gcs_uri(uri: str) -> tuple[str, str]:
    parsed = urlparse(uri)
    bucket, name = parsed.netloc, parsed.path.lstrip("/")
    if not bucket or not name:
        raise StorageError(f"URI de GCS inválida (se esperaba gs://bucket/objeto): {uri}")
    return bucket, name


ALLOWED_PREFIX_ENV = "SECXFER_ALLOWED_PREFIX"


def _check_allowed(uri: str) -> tuple[str, str]:
    """Valida la URI de GCS y que el objeto esté dentro de la carpeta permitida (si hay una configurada).

    Returns:
        (bucket, objeto) ya validados.
    """
    bucket, name = parse_gcs_uri(uri)
    allowed = os.environ.get(ALLOWED_PREFIX_ENV, "").strip()
    if allowed and not name.startswith(allowed):
        raise StorageError(f"{uri} está fuera de la carpeta permitida ({allowed})")
    return bucket, name


def _gcs():
    """Devuelve (cliente, módulo de excepciones). Import perezoso con error de dominio si falta la librería."""
    try:
        from google.api_core import exceptions as gexc
        from google.cloud import storage
    except ImportError as exc:
        raise StorageError("Falta la dependencia google-cloud-storage") from exc
    return storage.Client(), gexc


def _wrap_google_errors(action: str, uri: str, exc: Exception) -> StorageError:
    return StorageError(f"{action} {uri} falló ({type(exc).__name__}): {exc}")


def fetch(uri: str, dest: str | Path) -> None:
    """Descarga/copia `uri` al archivo local `dest`."""
    dest = Path(dest)
    if is_gcs(uri):
        bucket, name = _check_allowed(uri)
        client, gexc = _gcs()
        try:
            client.bucket(bucket).blob(name).download_to_filename(str(dest))
        except gexc.NotFound as exc:
            raise StorageError(f"No existe el objeto {uri}") from exc
        except gexc.GoogleAPICallError as exc:
            raise _wrap_google_errors("Descarga de", uri, exc) from exc
        return
    try:
        shutil.copyfile(uri, dest)
    except FileNotFoundError as exc:
        raise StorageError(f"No existe el archivo {uri}") from exc
    except OSError as exc:
        raise StorageError(f"No se pudo leer {uri}: {exc}") from exc


def put(src: str | Path, uri: str, overwrite: bool = False) -> None:
    """Sube/copia el archivo local `src` a `uri`."""
    src = Path(src)
    if is_gcs(uri):
        bucket, name = _check_allowed(uri)
        client, gexc = _gcs()
        try:
            client.bucket(bucket).blob(name).upload_from_filename(str(src), if_generation_match=None if overwrite else 0)
        except gexc.PreconditionFailed as exc:
            raise StorageError(f"{uri} ya existe (use --overwrite si es intencional)") from exc
        except gexc.GoogleAPICallError as exc:
            raise _wrap_google_errors("Subida a", uri, exc) from exc
        return
    target = Path(uri)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not overwrite:
            raise StorageError(f"{uri} ya existe (use --overwrite si es intencional)")
        tmp = target.with_name(target.name + ".uploading")
        shutil.copyfile(src, tmp)
        os.replace(tmp, target)
    except OSError as exc:
        raise StorageError(f"No se pudo escribir {uri}: {exc}") from exc


def basename(uri: str) -> str:
    return parse_gcs_uri(uri)[1].rsplit("/", 1)[-1] if is_gcs(uri) else Path(uri).name


def resolve_destination(destination: str, source: str, *, add_suffix: str = "", strip_suffix: str = "") -> str:
    """Si `destination` es una carpeta/prefijo (termina en '/' o es un directorio), le añade el
    nombre del origen (con sufijo añadido o quitado). Si es un nombre completo, se respeta tal cual."""
    is_prefix = destination.endswith("/") or (not is_gcs(destination) and Path(destination).is_dir())
    if not is_prefix:
        return destination
    name = basename(source)
    if strip_suffix and name.endswith(strip_suffix) and len(name) > len(strip_suffix):
        name = name[: -len(strip_suffix)]
    elif strip_suffix:
        name += ".recovered"
    name += add_suffix
    return destination.rstrip("/") + "/" + name
