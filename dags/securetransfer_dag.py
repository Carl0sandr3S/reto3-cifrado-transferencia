"""DAG de Airflow: orquesta los Cloud Run Jobs de securetransfer.

    esperar archivo en BRONZE/portal  ->  st-send (cifra a SILVER)  ->  st-receive (descifra a GOLD)  ->  st-verify
    ->  registrar_ejecucion (siempre; guarda el resultado en BigQuery)

Airflow NO cifra nada: solo dispara y vigila los jobs. Cada job conserva su propia identidad
(st-sender solo cifra, st-receiver solo descifra, st-verifier solo lee), así que la separación de
funciones sigue intacta. La cuenta del entorno de Airflow solo recibe permiso para EJECUTAR los jobs
(ver `python deploy/gcp.py grant-orchestrator`).

Pensado para Airflow 2.x (Cloud Composer, imagen `composer-3-airflow-2`): imports desde `airflow.models`.
No es compatible con Airflow 3, que mueve DAG y Param a `airflow.sdk`.
Requiere el proveedor `apache-airflow-providers-google` que trae la imagen de Composer (no hace falta instalarlo).

Auditoría: la última tarea (`registrar_ejecucion`) corre SIEMPRE, también si el flujo falló, y guarda una fila por
ejecución en BigQuery (`<proyecto>.auditoria.ejecuciones_airflow`). Ver dags/securetransfer_audit.py.

Arquitectura medallion: BRONZE (crudo) -> SILVER (cifrado) -> GOLD (recuperado y verificado). Todo el flujo trabaja
SOLO dentro de la carpeta `portal/` de cada capa; `object` es relativo a esa carpeta.

Disparo manual con parámetros (UI: "Trigger DAG w/ config"):
    {"project_id": "mi-proyecto", "object": "clientes.csv"}   # gs://<proyecto>-bronze/portal/clientes.csv
"""

from __future__ import annotations

from datetime import datetime, timedelta
from airflow.models.dag import DAG
from airflow.models.param import Param
from airflow.operators.python import PythonOperator
from airflow.providers.google.cloud.operators.cloud_run import CloudRunExecuteJobOperator
from airflow.providers.google.cloud.sensors.gcs import GCSObjectsWithPrefixExistenceSensor
from airflow.utils.trigger_rule import TriggerRule

from securetransfer_audit import TAREA_REGISTRO, registrar_ejecucion
from securetransfer_paths import (  # módulo auxiliar que se sube junto al DAG
    JOB_RECEIVER,
    JOB_SENDER,
    JOB_VERIFIER,
    overrides,
    plan_paths,
    receive_args,
    safe_segment,
    send_args,
    verify_args,
)


def _templated(base, *extra: str) -> tuple[str, ...]:
    """template_fields de la clase base + los campos que necesitamos que Airflow renderice con Jinja."""
    return tuple(dict.fromkeys((*getattr(base, "template_fields", ()), *extra)))


class RunJob(CloudRunExecuteJobOperator):
    # Se garantiza que estos campos se rendericen aunque la clase base ya los incluya.
    template_fields = _templated(CloudRunExecuteJobOperator, "project_id", "region", "job_name", "overrides")


class WaitForFile(GCSObjectsWithPrefixExistenceSensor):
    template_fields = _templated(GCSObjectsWithPrefixExistenceSensor, "bucket", "prefix")


# Expresiones Jinja: se resuelven en cada ejecución con los parámetros con que se dispara el DAG.
PROJECT = "{{ params.project_id }}"
REGION = "{{ params.region }}"
OBJECT = "{{ params.object }}"
RUN = "{{ safe(run_id) }}"
BASENAME = "{{ params.object.rsplit('/', 1)[-1] }}"

PATHS = plan_paths(PROJECT, RUN, OBJECT, basename=BASENAME)

with DAG(
    dag_id="securetransfer_cloud_run",
    description="Cifra y transfiere un archivo con los Cloud Run Jobs de securetransfer y verifica el resultado",
    start_date=datetime(2026, 1, 1),
    schedule=None,  # se dispara por parámetros/API; ver README para hacerlo por evento
    catchup=False,
    params={
        "project_id": Param("", type="string", minLength=1, description="ID del proyecto de GCP"),
        "region": Param("us-east1", type="string", description="Región de los Cloud Run Jobs"),
        "object": Param("", type="string", minLength=1, description="Objeto dentro de bronze/portal/, p. ej. clientes.csv"),
    },
    user_defined_macros={"safe": safe_segment},
    tags=["securetransfer", "cloud-run"],
) as dag:
    wait_for_file = WaitForFile(
        task_id="wait_for_file",
        bucket=PATHS.bronze_bucket,
        prefix=PATHS.prefix,
        mode="reschedule",  # libera el worker entre revisiones
        poke_interval=60,
        timeout=6 * 60 * 60,
    )

    # retries=0 en send/receive a propósito: los buckets son de solo creación (no se sobrescribe),
    # así que reintentar tras una subida ya hecha fallaría con "ya existe" y ocultaría la causa real.
    send = RunJob(
        task_id="send",
        project_id=PROJECT, region=REGION, job_name=JOB_SENDER,
        overrides=overrides(send_args(PATHS)),
        retries=0,
    )
    receive = RunJob(
        task_id="receive",
        project_id=PROJECT, region=REGION, job_name=JOB_RECEIVER,
        overrides=overrides(receive_args(PATHS)),
        retries=0,
    )
    # La verificación es de solo lectura: reintentarla es seguro.
    verify = RunJob(
        task_id="verify",
        project_id=PROJECT, region=REGION, job_name=JOB_VERIFIER,
        overrides=overrides(verify_args(PATHS)),
        retries=1, retry_delay=timedelta(minutes=2),
    )

    # Auditoría en BigQuery. all_done: corre también si send/receive/verify fallaron (o se saltaron por una falla previa).
    # retries=0: registrar dos veces la misma corrida ensuciaría la auditoría.
    registrar = PythonOperator(
        task_id=TAREA_REGISTRO,
        python_callable=registrar_ejecucion,
        trigger_rule=TriggerRule.ALL_DONE,
        retries=0,
    )

    wait_for_file >> send >> receive >> verify >> registrar
