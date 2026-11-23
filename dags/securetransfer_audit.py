"""Auditoría del DAG en BigQuery: una fila por ejecución (exitosa o fallida) en `auditoria.ejecuciones_airflow`.

Lógica pura, sin importar Airflow: se puede probar sin él. El DAG la usa en su última tarea (`registrar_ejecucion`),
que corre SIEMPRE (trigger_rule all_done): también cuando el flujo falló.

La tabla es compartida con otros DAGs (la columna `nombre_dag` los distingue) y se crea con
`python deploy/composer.py audit-table` (o `wire`). Sus columnas deben coincidir con AUDIT_COLUMNS de deploy/gcp.py;
una prueba lo comprueba.

Seguridad: la fila solo lleva identificadores y estados (run_id, tarea fallida, URL del log). NO lleva contenido de
archivos, hashes ni llaves. El INSERT usa parámetros: los valores nunca se pegan en el texto SQL.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

DATASET = "auditoria"
TABLE = "ejecuciones_airflow"
TAREA_REGISTRO = "registrar_ejecucion"

# columna -> tipo de BigQuery, en el orden de la tabla
TIPOS = {
    "id": "STRING",                       # identificador único de la fila (uuid)
    "nombre_dag": "STRING",
    "run_id": "STRING",                   # identificador de la corrida en Airflow (en el portal: portal-<fecha>-<usuario>-<id>)
    "tipo_ejecucion": "STRING",           # scheduled / manual
    "fecha_logica": "TIMESTAMP",          # periodo de datos que representa la corrida
    "fecha_hora_ejecucion": "TIMESTAMP",  # cuándo empezó a ejecutarse
    "fecha_hora_fin": "TIMESTAMP",
    "duracion_segundos": "INT64",
    "estado_ejecucion": "STRING",         # EXITOSO / FALLIDO
    "tarea_fallida": "STRING",            # primera tarea que falló (vacío si fue exitosa)
    "url_log": "STRING",                  # enlace al log de esa tarea en Airflow
}


class PipelineFallido(RuntimeError):
    """El flujo falló. Se lanza DESPUÉS de registrar la fila, para que Airflow no marque la corrida como exitosa
    solo porque esta última tarea terminó bien."""


def tabla(project: str) -> str:
    """Nombre completo de la tabla (proyecto.dataset.tabla)."""
    return f"{project}.{DATASET}.{TABLE}"


def _texto(valor):
    """Los estados de Airflow son enums: devuelve su texto ('failed', 'scheduled', ...)."""
    return getattr(valor, "value", valor)


def construir_fila(dag_run, tareas, ahora: datetime, id_fila: str) -> dict:
    """Arma la fila de auditoría de una corrida. `tareas`: las tareas de la corrida y su estado.
    Es FALLIDO si alguna tarea falló o no pudo correr por una falla anterior (upstream_failed)."""
    otras = [t for t in tareas if t.task_id != TAREA_REGISTRO]  # esta tarea no se juzga a sí misma
    falladas = [t for t in otras if _texto(t.state) == "failed"]
    fallido = bool(falladas) or any(_texto(t.state) == "upstream_failed" for t in otras)
    inicio = dag_run.start_date or ahora
    return {
        "id": id_fila,
        "nombre_dag": dag_run.dag_id,
        "run_id": dag_run.run_id,
        "tipo_ejecucion": _texto(dag_run.run_type),
        "fecha_logica": getattr(dag_run, "logical_date", None),
        "fecha_hora_ejecucion": inicio,
        "fecha_hora_fin": ahora,
        "duracion_segundos": int((ahora - inicio).total_seconds()),
        "estado_ejecucion": "FALLIDO" if fallido else "EXITOSO",
        "tarea_fallida": falladas[0].task_id if falladas else None,
        "url_log": getattr(falladas[0], "log_url", None) if falladas else None,
    }


def insertar_fila(cliente, project: str, fila: dict) -> None:
    """INSERT con parámetros sobre la tabla de auditoría. Si falla, la excepción sube y la tarea falla (se ve en Airflow)."""
    from google.cloud import bigquery  # se importa aquí: en Composer ya viene instalado; en las pruebas no hace falta

    columnas = list(TIPOS)
    sql = (f"INSERT INTO `{tabla(project)}` ({', '.join(columnas)}) "
           f"VALUES ({', '.join('@' + c for c in columnas)})")
    parametros = [bigquery.ScalarQueryParameter(c, TIPOS[c], fila[c]) for c in columnas]
    cliente.query(sql, job_config=bigquery.QueryJobConfig(query_parameters=parametros)).result()


def registrar_ejecucion(**contexto) -> None:
    """Guarda el resultado de la corrida en BigQuery. Corre siempre (all_done), también si algo falló.

    El proyecto y la región salen de los parámetros del DAG (`project_id`, `region`): la tabla vive en el mismo
    proyecto y región que los Cloud Run Jobs (la crea `deploy/composer.py audit-table`).

    Raises:
        PipelineFallido: si alguna tarea del flujo falló (después de registrar).
    """
    from google.cloud import bigquery

    params = contexto["params"]
    project, region = params["project_id"], params["region"]
    dag_run = contexto["dag_run"]
    fila = construir_fila(dag_run, dag_run.get_task_instances(), datetime.now(timezone.utc), str(uuid.uuid4()))
    insertar_fila(bigquery.Client(project=project, location=region), project, fila)
    logging.info("Ejecución registrada en %s: id=%s estado=%s", tabla(project), fila["id"], fila["estado_ejecucion"])
    if fila["estado_ejecucion"] == "FALLIDO":
        raise PipelineFallido(f"El flujo falló en la tarea '{fila['tarea_fallida']}'. "
                              f"Quedó registrado en {tabla(project)} (id {fila['id']}).")
