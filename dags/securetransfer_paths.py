"""Lógica pura del DAG (rutas y argumentos de los jobs). No importa Airflow: se puede probar sin él.

Las funciones aceptan texto normal O expresiones Jinja (`{{ params.object }}`): el DAG les pasa plantillas
y Airflow las renderiza en tiempo de ejecución. Las pruebas las pasan con valores reales.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Debe coincidir con CONTAINER_NAME de deploy/gcp.py (el nombre con el que se despliegan los jobs).
CONTAINER_NAME = "job"
JOB_SENDER = "st-send"
JOB_RECEIVER = "st-receive"
JOB_VERIFIER = "st-verify"

# Arquitectura medallion: cada capa es un bucket. El flujo SOLO lee y escribe dentro de la carpeta FLOW_FOLDER
# de cada capa (debe coincidir con FLOW_FOLDER de deploy/gcp.py y con portal/store.py; una prueba lo comprueba).
BRONZE = "bronze"  # dato crudo tal como lo sube la interfaz
SILVER = "silver"  # dato protegido: cifrado con KMS
GOLD = "gold"      # dato recuperado, verificado y listo para consumir
FLOW_FOLDER = "portal"

_UNSAFE = re.compile(r"[^A-Za-z0-9_.-]")


def safe_segment(value: str) -> str:
    """Convierte un run_id de Airflow (p. ej. 'manual__2026-11-20T22:00:00+00:00') en un tramo
    de ruta limpio para GCS: sin ':', '+' ni espacios."""
    cleaned = _UNSAFE.sub("_", str(value)).strip(".")
    return cleaned or "run"


@dataclass(frozen=True)
class Paths:
    bronze_bucket: str
    src: str          # original en BRONZE
    transit_dir: str  # carpeta de esta ejecución en SILVER
    enc: str          # archivo cifrado en SILVER
    out_dir: str      # carpeta de esta ejecución en GOLD
    out: str          # archivo recuperado en GOLD
    prefix: str       # objeto dentro de BRONZE (siempre bajo portal/): para el sensor


def plan_paths(project: str, run: str, obj: str, basename: str | None = None) -> Paths:
    """Rutas de una ejecución. `obj` es relativo a la carpeta `portal/` de BRONZE (p. ej. '<run>/<archivo>'):
    el flujo antepone siempre `portal/`, así que ni siquiera con un parámetro manipulado puede leer fuera de ella.
    Cada ejecución usa su propia carpeta: los buckets no permiten sobrescribir, así que reejecutar con el
    mismo archivo nunca choca con una ejecución anterior."""
    name = basename if basename is not None else obj.rsplit("/", 1)[-1]
    bronze, silver, gold = (f"{project}-{layer}" for layer in (BRONZE, SILVER, GOLD))
    f = FLOW_FOLDER
    return Paths(
        bronze_bucket=bronze,
        src=f"gs://{bronze}/{f}/{obj}",
        transit_dir=f"gs://{silver}/{f}/{run}/",
        enc=f"gs://{silver}/{f}/{run}/{name}.enc",
        out_dir=f"gs://{gold}/{f}/{run}/",
        out=f"gs://{gold}/{f}/{run}/{name}",
        prefix=f"{f}/{obj}",
    )


def send_args(p: Paths) -> list[str]:
    return ["send", "--source", p.src, "--destination", p.transit_dir]


def receive_args(p: Paths) -> list[str]:
    return ["receive", "--source", p.enc, "--destination", p.out_dir]


def verify_args(p: Paths) -> list[str]:
    return ["verify", "--original", p.src, "--recovered", p.out]


def overrides(args: list[str]) -> dict:
    """Estructura `overrides` de CloudRunExecuteJobOperator: reemplaza los argumentos del contenedor
    solo para esta ejecución (el job queda definido una vez, con su imagen y su identidad)."""
    return {"container_overrides": [{"name": CONTAINER_NAME, "args": list(args)}], "task_count": 1}
