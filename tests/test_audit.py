"""Auditoría en BigQuery: una fila por ejecución del DAG (exitosa o fallida) en auditoria.ejecuciones_airflow.

No hay Airflow ni BigQuery en el entorno de pruebas: se usan dobles. Lo que NO se prueba aquí es el INSERT real contra
BigQuery ni la ejecución del DAG en Composer (ver README: «Lo que no pude verificar»).
"""

import importlib.util
import sys
import types
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path

import pytest

import securetransfer_audit as audit
from deploy import gcp
from deploy.composer import cmd_wire

REPO = Path(__file__).resolve().parent.parent
PROJECT = "demo-proj"
AHORA = datetime(2026, 11, 22, 18, 0, 30, tzinfo=timezone.utc)
INICIO = AHORA - timedelta(seconds=90)


class _Estado(Enum):
    FAILED = "failed"
    SUCCESS = "success"
    UPSTREAM_FAILED = "upstream_failed"


class _Tipo(Enum):
    MANUAL = "manual"


class _Tarea:
    def __init__(self, task_id, state, log_url=None):
        self.task_id, self.state, self.log_url = task_id, state, log_url


def _corrida(start=INICIO):
    return types.SimpleNamespace(dag_id="securetransfer_cloud_run", run_id="portal-20261122T175900Z-maria-a1b2c3",
                                 run_type=_Tipo.MANUAL, logical_date=INICIO, start_date=start)


# --------------------------------------------------------------------- construir_fila


def test_fila_exitosa_incluye_todas_las_columnas_en_orden():
    tareas = [_Tarea(t, _Estado.SUCCESS) for t in ("wait_for_file", "send", "receive", "verify")]
    tareas.append(_Tarea(audit.TAREA_REGISTRO, "running"))  # la tarea de registro no se juzga a sí misma
    fila = audit.construir_fila(_corrida(), tareas, AHORA, "id-1")
    assert list(fila) == list(audit.TIPOS)
    assert fila["estado_ejecucion"] == "EXITOSO" and fila["tarea_fallida"] is None and fila["url_log"] is None
    assert fila["duracion_segundos"] == 90
    assert fila["tipo_ejecucion"] == "manual"  # el enum se convierte a texto
    assert fila["nombre_dag"] == "securetransfer_cloud_run" and fila["id"] == "id-1"


def test_fila_fallida_reporta_la_primera_tarea_que_fallo_y_su_log():
    tareas = [_Tarea("wait_for_file", _Estado.SUCCESS), _Tarea("send", _Estado.SUCCESS),
              _Tarea("receive", _Estado.FAILED, log_url="https://airflow/log?task=receive"),
              _Tarea("verify", _Estado.UPSTREAM_FAILED)]
    fila = audit.construir_fila(_corrida(), tareas, AHORA, "id-2")
    assert fila["estado_ejecucion"] == "FALLIDO"
    assert fila["tarea_fallida"] == "receive" and fila["url_log"] == "https://airflow/log?task=receive"


def test_solo_upstream_failed_tambien_es_fallido():
    # p. ej. el sensor agotó el tiempo y las demás se saltaron: no hay 'failed' pero la corrida no fue exitosa
    tareas = [_Tarea("wait_for_file", _Estado.SUCCESS), _Tarea("send", _Estado.UPSTREAM_FAILED)]
    assert audit.construir_fila(_corrida(), tareas, AHORA, "i")["estado_ejecucion"] == "FALLIDO"


def test_sin_start_date_la_duracion_es_cero():
    fila = audit.construir_fila(_corrida(start=None), [], AHORA, "i")
    assert fila["duracion_segundos"] == 0 and fila["fecha_hora_ejecucion"] == AHORA


# --------------------------------------------------------------------- BigQuery con dobles


class _Param:
    def __init__(self, name, tipo, valor):
        self.name, self.tipo, self.valor = name, tipo, valor


class _Cliente:
    def __init__(self, **kw):
        self.kw, self.consultas = kw, []

    def query(self, sql, job_config=None):
        self.consultas.append((sql, job_config.query_parameters))
        return types.SimpleNamespace(result=lambda: None)


@pytest.fixture
def bq(monkeypatch):
    """Instala un google.cloud.bigquery falso y devuelve la lista de clientes creados."""
    clientes = []

    def client(**kw):
        c = _Cliente(**kw)
        clientes.append(c)
        return c

    mod = types.ModuleType("google.cloud.bigquery")
    mod.ScalarQueryParameter = _Param
    mod.QueryJobConfig = lambda query_parameters: types.SimpleNamespace(query_parameters=query_parameters)
    mod.Client = client
    cloud = types.ModuleType("google.cloud")
    cloud.bigquery = mod
    monkeypatch.setitem(sys.modules, "google", types.ModuleType("google"))
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.bigquery", mod)
    return clientes


def test_el_insert_usa_parametros_y_la_tabla_correcta(bq):
    fila = audit.construir_fila(_corrida(), [_Tarea("send", _Estado.SUCCESS)], AHORA, "id-3")
    cliente = _Cliente()
    audit.insertar_fila(cliente, PROJECT, fila)
    (sql, params), = cliente.consultas
    assert sql.startswith("INSERT INTO `demo-proj.auditoria.ejecuciones_airflow` (id, nombre_dag,")
    assert sql.count("@") == 11 and "securetransfer_cloud_run" not in sql  # los valores NO van en el texto SQL
    assert [(p.name, p.tipo) for p in params] == list(audit.TIPOS.items())
    assert {p.name: p.valor for p in params}["run_id"] == fila["run_id"]


def _contexto(tareas, project=PROJECT, region="us-east1"):
    run = _corrida()
    run.get_task_instances = lambda: tareas
    return {"dag_run": run, "params": {"project_id": project, "region": region}}


def test_registrar_ejecucion_exitosa_inserta_y_no_falla(bq):
    audit.registrar_ejecucion(**_contexto([_Tarea("verify", _Estado.SUCCESS)]))
    (cliente,) = bq
    assert cliente.kw == {"project": PROJECT, "location": "us-east1"}  # proyecto y región salen de los params del DAG
    assert len(cliente.consultas) == 1


def test_registrar_ejecucion_fallida_inserta_y_DESPUES_falla(bq):
    tareas = [_Tarea("send", _Estado.FAILED, log_url="https://airflow/log"), _Tarea("receive", _Estado.UPSTREAM_FAILED)]
    with pytest.raises(audit.PipelineFallido, match="'send'"):
        audit.registrar_ejecucion(**_contexto(tareas))
    (cliente,) = bq
    valores = {p.name: p.valor for p in cliente.consultas[0][1]}
    assert valores["estado_ejecucion"] == "FALLIDO" and valores["tarea_fallida"] == "send"  # quedó registrada


def test_si_bigquery_falla_la_tarea_falla_y_no_se_oculta(bq, monkeypatch):
    def roto(self, sql, job_config=None):
        raise RuntimeError("403 sin permiso")

    monkeypatch.setattr(_Cliente, "query", roto)
    with pytest.raises(RuntimeError, match="403"):
        audit.registrar_ejecucion(**_contexto([_Tarea("verify", _Estado.SUCCESS)]))


# --------------------------------------------------------------------- el DAG (con Airflow simulado)


@pytest.fixture
def dag(monkeypatch):
    """Carga dags/securetransfer_dag.py con un Airflow mínimo falso y devuelve el DAG resultante."""

    class Dag:
        current = None

        def __init__(self, **kw):
            self.kw, self.tasks = kw, {}

        def __enter__(self):
            Dag.current = self
            return self

        def __exit__(self, *a):
            Dag.current = None

    class Op:
        template_fields = ()

        def __init__(self, task_id, **kw):
            self.task_id, self.kw, self.upstream = task_id, kw, set()
            Dag.current.tasks[task_id] = self

        def __rshift__(self, other):
            other.upstream.add(self.task_id)
            return other

    class Trigger:
        ALL_DONE = "all_done"

    def modulo(nombre, **attrs):
        m = types.ModuleType(nombre)
        m.__dict__.update(attrs)
        monkeypatch.setitem(sys.modules, nombre, m)

    for pkg in ("airflow", "airflow.models", "airflow.operators", "airflow.providers", "airflow.providers.google",
                "airflow.providers.google.cloud", "airflow.providers.google.cloud.operators",
                "airflow.providers.google.cloud.sensors", "airflow.utils"):
        modulo(pkg)
    modulo("airflow.models.dag", DAG=Dag)
    modulo("airflow.models.param", Param=lambda *a, **k: ("param", a, k))
    modulo("airflow.operators.python", PythonOperator=Op)
    modulo("airflow.providers.google.cloud.operators.cloud_run", CloudRunExecuteJobOperator=Op)
    modulo("airflow.providers.google.cloud.sensors.gcs", GCSObjectsWithPrefixExistenceSensor=Op)
    modulo("airflow.utils.trigger_rule", TriggerRule=Trigger)

    spec = importlib.util.spec_from_file_location("dag_bajo_prueba", REPO / "dags" / "securetransfer_dag.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.dag


def test_el_dag_termina_en_registrar_y_corre_aunque_algo_falle(dag):
    t = dag.tasks
    assert list(t) == ["wait_for_file", "send", "receive", "verify", audit.TAREA_REGISTRO]
    assert t["send"].upstream == {"wait_for_file"} and t["verify"].upstream == {"receive"}
    registrar = t[audit.TAREA_REGISTRO]
    assert registrar.upstream == {"verify"}
    assert registrar.kw["trigger_rule"] == "all_done"  # también si send/receive/verify fallaron
    assert registrar.kw["retries"] == 0                # no duplicar la fila de auditoría
    assert registrar.kw["python_callable"] is audit.registrar_ejecucion


# --------------------------------------------------------------------- despliegue


def test_las_columnas_del_despliegue_coinciden_con_las_del_modulo_de_auditoria():
    assert dict(gcp.AUDIT_COLUMNS) == audit.TIPOS and [c for c, _ in gcp.AUDIT_COLUMNS] == list(audit.TIPOS)
    assert (gcp.AUDIT_DATASET, gcp.AUDIT_TABLE) == (audit.DATASET, audit.TABLE)


def test_audit_sql_crea_dataset_y_tabla_idempotentes_y_da_acceso_solo_a_la_tabla():
    sa = f"st-orchestrator@{PROJECT}.iam.gserviceaccount.com"
    schema, table, grant = gcp.audit_sql(PROJECT, "us-east1", sa)
    assert schema == 'CREATE SCHEMA IF NOT EXISTS `demo-proj.auditoria` OPTIONS (location = "us-east1")'
    assert table.startswith("CREATE TABLE IF NOT EXISTS `demo-proj.auditoria.ejecuciones_airflow`")
    assert all(f"{c} {k}" in table for c, k in audit.TIPOS.items())
    assert grant == (f'GRANT `roles/bigquery.dataEditor` ON TABLE `demo-proj.auditoria.ejecuciones_airflow` '
                     f'TO "serviceAccount:{sa}"')
    assert len(gcp.audit_sql(PROJECT, "us-east1")) == 2  # sin cuenta: solo crea


@pytest.mark.parametrize("project", ["", "A;DROP", "demo`proj", "x" * 80, "demo proj"])
def test_audit_sql_rechaza_ids_que_podrian_inyectar_sql(project):
    with pytest.raises(gcp.DeployError):
        gcp.audit_sql(project, "us-east1")


def test_audit_sql_rechaza_cuentas_y_ubicaciones_raras():
    with pytest.raises(gcp.DeployError):
        gcp.audit_sql(PROJECT, "us-east1", 'x@y.iam.gserviceaccount.com"; DROP')
    with pytest.raises(gcp.DeployError):
        gcp.audit_sql(PROJECT, 'us"; DROP')


def _dry(fn, *args):
    g = gcp.Gcloud(PROJECT, dry_run=True)
    fn(gcp.Config(PROJECT), g, *args)
    return g.history


def test_audit_table_sin_cuenta_solo_crea_y_no_concede_permisos():
    history = _dry(gcp.cmd_audit_table)
    assert history[0][:4] == ["gcloud", "services", "enable", "bigquery.googleapis.com"]
    assert [c[0] for c in history[1:]] == ["bq", "bq"]
    assert not any("add-iam-policy-binding" in c or "GRANT" in " ".join(c) for c in history)


def test_wire_da_a_airflow_jobuser_y_dataeditor_solo_sobre_la_tabla_y_sube_el_modulo_de_auditoria():
    history = _dry(cmd_wire, "st-airflow")
    sa = f"serviceAccount:st-orchestrator@{PROJECT}.iam.gserviceaccount.com"
    jobuser = [c for c in history if "roles/bigquery.jobUser" in c]
    assert len(jobuser) == 1 and sa in jobuser[0]
    grants = [c[-1] for c in history if c[0] == "bq" and "GRANT" in c[-1]]
    assert grants == [f'GRANT `roles/bigquery.dataEditor` ON TABLE `demo-proj.auditoria.ejecuciones_airflow` TO "{sa}"']
    assert not any("bigquery.dataEditor" in " ".join(c) for c in history if c[0] == "gcloud")  # nada a nivel de proyecto
    subidos = [Path(c[c.index("--source") + 1]).name for c in history if "import" in c]
    assert subidos == ["securetransfer_paths.py", "securetransfer_audit.py", "securetransfer_dag.py"]  # módulos antes del DAG
    # la tabla existe antes de dar permisos sobre ella
    creada = next(i for i, c in enumerate(history) if c[0] == "bq" and "CREATE TABLE" in c[-1])
    concedida = next(i for i, c in enumerate(history) if c[0] == "bq" and "GRANT" in c[-1])
    assert creada < concedida
