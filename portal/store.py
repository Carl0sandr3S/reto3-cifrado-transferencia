"""Almacenamiento del portal (arquitectura medallion): ESCRIBE en BRONZE (solo crear) y LEE de GOLD (solo leer).

Todo lo de la interfaz vive en la carpeta `portal/` de cada capa. El resto de la aplicación trabaja con nombres
RELATIVOS a esa carpeta (`<run_id>/<archivo>`); aquí se antepone `portal/` al hablar con el bucket, así que ningún
código del portal puede salir de ella.

El portal nunca toca SILVER (donde queda lo cifrado) ni la llave KMS: el cifrado lo hace el flujo securetransfer.
Los permisos de la cuenta de servicio del portal lo refuerzan (ver deploy/portal.py):
  - BRONZE: roles/storage.objectCreator -> puede crear en portal/, NO leer ni listar lo que subió
  - GOLD  : roles/storage.objectViewer  -> puede leer en portal/ (condición IAM por prefijo) + listar el bucket

Mismos nombres de objeto en las tres capas: `portal/<run_id>/<archivo>` (igual que el DAG de Airflow).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


class StoreError(Exception):
    """Error de almacenamiento (mensaje apto para registrar, sin datos sensibles)."""


class AlreadyExists(StoreError):
    """El objeto ya existe: los buckets no permiten sobrescribir."""


class NotFound(StoreError):
    """El objeto no existe."""


FLOW_FOLDER = "portal"  # carpeta de cada capa; debe coincidir con dags/securetransfer_paths.py y deploy/gcp.py


@dataclass(frozen=True)
class Entry:
    name: str       # "<run_id>/<archivo>" (relativo a portal/)
    size: int       # bytes
    updated: float  # epoch (segundos)


class LocalStore:
    """Desarrollo y pruebas: carpetas que replican los buckets (root/bronze/portal, root/silver/portal, root/gold/portal)."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.bronze = self.root / "bronze" / FLOW_FOLDER
        self.silver = self.root / "silver" / FLOW_FOLDER
        self.gold = self.root / "gold" / FLOW_FOLDER
        for layer in (self.bronze, self.silver, self.gold):
            layer.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _resolve(base: Path, name: str) -> Path:
        path = (base / name).resolve()
        if base.resolve() not in path.parents:  # defensa extra contra path traversal
            raise StoreError("Nombre de objeto no válido")
        return path

    def put_bronze(self, name: str, data: bytes) -> None:
        path = self._resolve(self.bronze, name)
        if path.exists():
            raise AlreadyExists(f"{name} ya existe")
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".uploading")
        tmp.write_bytes(data)
        os.replace(tmp, path)  # atómico: el flujo nunca ve un archivo a medias

    def list_gold(self, prefix: str = "") -> list[Entry]:
        out = []
        for p in self.gold.rglob("*"):
            if p.is_file():
                rel = p.relative_to(self.gold).as_posix()
                if rel.startswith(prefix):
                    st = p.stat()
                    out.append(Entry(rel, st.st_size, st.st_mtime))
        return out

    def get_gold(self, name: str) -> bytes:
        path = self._resolve(self.gold, name)
        if not path.is_file():
            raise NotFound(name)
        return path.read_bytes()


class GcsStore:
    """Producción: buckets de Cloud Storage (capas bronze y gold). La biblioteca de Google se importa solo si se usa."""

    def __init__(self, bucket_bronze: str, bucket_gold: str, client=None):
        if client is None:
            try:
                from google.cloud import storage
            except ImportError as exc:
                raise StoreError("Falta la dependencia google-cloud-storage") from exc
            client = storage.Client()
        self._client = client
        self._bronze, self._gold = bucket_bronze, bucket_gold

    @staticmethod
    def _key(name: str) -> str:
        """Nombre real en el bucket: siempre dentro de portal/."""
        return f"{FLOW_FOLDER}/{name}"

    def put_bronze(self, name: str, data: bytes) -> None:
        blob = self._client.bucket(self._bronze).blob(self._key(name))
        try:
            # if_generation_match=0: falla si ya existe. Es lo que permite dar solo objectCreator.
            blob.upload_from_string(data, content_type="application/octet-stream", if_generation_match=0)
        except Exception as exc:  # frontera con la API externa: se traduce a un error de dominio
            if getattr(exc, "code", None) == 412:
                raise AlreadyExists(f"{name} ya existe") from exc
            raise StoreError(f"No se pudo subir a bronze ({type(exc).__name__})") from exc

    def list_gold(self, prefix: str = "") -> list[Entry]:
        try:
            blobs = list(self._client.list_blobs(self._gold, prefix=self._key(prefix)))
        except Exception as exc:
            raise StoreError(f"No se pudo listar gold ({type(exc).__name__})") from exc
        cut = len(FLOW_FOLDER) + 1  # se devuelve el nombre relativo a portal/
        return [Entry(b.name[cut:], int(b.size or 0), b.updated.timestamp() if b.updated else 0.0)
                for b in blobs if not b.name.endswith("/")]

    def get_gold(self, name: str) -> bytes:
        try:
            return self._client.bucket(self._gold).blob(self._key(name)).download_as_bytes()
        except Exception as exc:
            if getattr(exc, "code", None) == 404:
                raise NotFound(name) from exc
            raise StoreError(f"No se pudo leer de gold ({type(exc).__name__})") from exc
