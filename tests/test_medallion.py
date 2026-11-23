"""Pruebas de la arquitectura medallion: BRONZE (crudo) -> SILVER (cifrado) -> GOLD (recuperado), todo bajo portal/.

Comprueban que las tres piezas que se despliegan por separado (DAG de Airflow, portal y despliegue con gcloud)
no se desvíen entre sí y que ninguna pueda leer o escribir fuera de la carpeta portal/.
"""

import pytest

import portal.store as portal_store
import portal.trigger as portal_trigger
import securetransfer_paths as dag_paths
from deploy import gcp
from deploy.composer import cmd_trigger, cmd_wire
from deploy.portal import cmd_infra as portal_infra
from portal.store import LocalStore
from portal.trigger import job_calls
from securetransfer import storage
from securetransfer.errors import StorageError

PROJECT = "demo-proj"
RUN = "portal-20261121T000000Z-maria-abc123"
OBJ = f"{RUN}/oferta.pdf"


def _dry(cmd, *args, **kwargs):
    """Ejecuta un comando de despliegue en dry-run y devuelve los comandos de gcloud que habría lanzado."""
    g = gcp.Gcloud(PROJECT, dry_run=True)
    cmd(gcp.Config(PROJECT), g, *args, **kwargs)
    return g.history


def _bucket_bindings(history):
    """(bucket, miembro, rol, condición) de cada add-iam-policy-binding sobre buckets."""
    out = []
    for c in history:
        if c[1:4] == ["storage", "buckets", "add-iam-policy-binding"]:
            opts = dict(zip(c[5:], c[6:]))
            cond = next(a for a in c if a.startswith("--condition="))[len("--condition="):]
            out.append((c[4], opts["--member"], opts["--role"], cond))
    return out


# --------------------------------------------------------------------- una sola carpeta en todas partes


def test_la_carpeta_es_la_misma_en_dag_portal_y_despliegue():
    assert dag_paths.FLOW_FOLDER == portal_store.FLOW_FOLDER == portal_trigger.FLOW_FOLDER == gcp.FLOW_FOLDER == "portal"
    assert (dag_paths.BRONZE, dag_paths.SILVER, dag_paths.GOLD) == (gcp.LAYER_BRONZE, gcp.LAYER_SILVER, gcp.LAYER_GOLD)


def test_los_buckets_son_las_tres_capas():
    cfg = gcp.Config(PROJECT)
    assert (cfg.bucket_bronze, cfg.bucket_silver, cfg.bucket_gold) == (
        "demo-proj-bronze", "demo-proj-silver", "demo-proj-gold")


def test_el_dag_solo_usa_rutas_dentro_de_portal():
    p = dag_paths.plan_paths(PROJECT, RUN, OBJ)
    assert p.src == f"gs://demo-proj-bronze/portal/{OBJ}"
    assert p.enc == f"gs://demo-proj-silver/portal/{RUN}/oferta.pdf.enc"
    assert p.out == f"gs://demo-proj-gold/portal/{RUN}/oferta.pdf"
    assert p.prefix == f"portal/{OBJ}" and p.bronze_bucket == "demo-proj-bronze"
    for uri in (p.src, p.transit_dir, p.enc, p.out_dir, p.out):
        assert "/portal/" in uri


def test_un_parametro_object_manipulado_no_sale_de_portal():
    # Aunque el parámetro del DAG intente apuntar a otra carpeta, el flujo antepone portal/: queda DENTRO de ella.
    p = dag_paths.plan_paths(PROJECT, RUN, "otra-carpeta/secreto.csv")
    assert p.src == "gs://demo-proj-bronze/portal/otra-carpeta/secreto.csv"


def test_el_portal_y_el_dag_calculan_las_mismas_rutas():
    p = dag_paths.plan_paths(PROJECT, RUN, OBJ)
    calls = dict(job_calls(PROJECT, RUN, OBJ))
    assert calls["st-send"] == dag_paths.send_args(p)
    assert calls["st-receive"] == dag_paths.receive_args(p)
    assert calls["st-verify"] == dag_paths.verify_args(p)


def test_la_demo_y_composer_tambien_trabajan_dentro_de_portal():
    cfg = gcp.Config(PROJECT)
    assert cfg.flow_uri(cfg.bucket_bronze, "r", "a.csv") == "gs://demo-proj-bronze/portal/r/a.csv"
    history = _dry(cmd_trigger, "st-airflow", "clientes.csv", upload=gcp.Path("clientes.csv"))
    assert ["gcloud", "storage", "cp", "clientes.csv", "gs://demo-proj-bronze/portal/clientes.csv"] == history[0][:5]


def test_el_store_local_replica_las_capas(tmp_path):
    LocalStore(tmp_path)
    for layer in ("bronze", "silver", "gold"):
        assert (tmp_path / layer / "portal").is_dir()
    assert not (tmp_path / "origen").exists()


# --------------------------------------------------------------------- IAM: solo la carpeta portal/


def test_infra_crea_las_tres_capas_y_ningun_bucket_antiguo():
    created = [c[4] for c in _dry(gcp.cmd_infra) if c[1:4] == ["storage", "buckets", "create"]]
    assert created == ["gs://demo-proj-bronze", "gs://demo-proj-silver", "gs://demo-proj-gold"]


def test_infra_limita_todos_los_permisos_de_objetos_a_portal():
    bindings = _bucket_bindings(_dry(gcp.cmd_infra))
    assert len(bindings) == 6
    for bucket, _member, _role, cond in bindings:
        assert cond == (f'title=solo-portal,expression=resource.name.startsWith('
                        f'"projects/_/buckets/{bucket[len("gs://"):]}/objects/portal/")')
    by = {(b[len("gs://"):], m.split(":")[1].split("@")[0], r.split(".")[-1]) for b, m, r, _ in bindings}
    assert by == {
        ("demo-proj-bronze", "st-sender", "objectViewer"), ("demo-proj-silver", "st-sender", "objectCreator"),
        ("demo-proj-silver", "st-receiver", "objectViewer"), ("demo-proj-gold", "st-receiver", "objectCreator"),
        ("demo-proj-bronze", "st-verifier", "objectViewer"), ("demo-proj-gold", "st-verifier", "objectViewer"),
    }


def test_el_portal_lee_y_crea_solo_en_portal_y_solo_lista_nombres_en_gold():
    history = _dry(portal_infra, "airflow")
    by_bucket = {}
    for bucket, _m, role, cond in _bucket_bindings(history):
        by_bucket.setdefault(bucket, []).append((role.split("/")[1], cond != "None"))
    assert by_bucket["gs://demo-proj-bronze"] == [("storage.objectCreator", True)]
    assert by_bucket["gs://demo-proj-gold"] == [("storage.objectViewer", True), ("storage.legacyBucketReader", False)]
    assert "gs://demo-proj-silver" not in by_bucket  # el portal no toca SILVER (lo cifrado)


def test_airflow_solo_lista_bronze_y_no_lee_objetos():
    history = _dry(cmd_wire, "st-airflow")
    (binding,) = [b for b in _bucket_bindings(history) if b[0] == "gs://demo-proj-bronze"]
    assert binding[2] == "roles/storage.legacyBucketReader" and binding[3] == "None"  # lista, no lee


def test_los_jobs_reciben_la_guarda_de_carpeta():
    deploys = [c for c in _dry(gcp.cmd_deploy_jobs, "img") if c[1:4] == ["run", "jobs", "deploy"]]
    assert len(deploys) == 3
    for c in deploys:
        assert "SECXFER_ALLOWED_PREFIX=portal/" in c[c.index("--set-env-vars") + 1].split(",")


# --------------------------------------------------------------------- guarda en la aplicación (segunda barrera)


@pytest.fixture
def solo_portal(monkeypatch):
    monkeypatch.setenv("SECXFER_ALLOWED_PREFIX", "portal/")


def test_los_jobs_se_niegan_a_leer_o_escribir_fuera_de_portal(solo_portal, tmp_path):
    f = tmp_path / "x"
    f.write_bytes(b"1")
    for uri in ("gs://b-bronze/otra/a.csv", "gs://b-bronze/a.csv", "gs://b-bronze/portalx/a.csv"):
        with pytest.raises(StorageError, match="fuera de la carpeta"):
            storage.fetch(uri, f)
        with pytest.raises(StorageError, match="fuera de la carpeta"):
            storage.put(f, uri)


def test_dentro_de_portal_la_guarda_deja_pasar(solo_portal, tmp_path, monkeypatch):
    llamadas = []

    class Blob:
        def download_to_filename(self, dest):
            llamadas.append(("get", dest))

    class Bucket:
        def blob(self, name):
            llamadas.append(("blob", name))
            return Blob()

    class Client:
        def bucket(self, name):
            return Bucket()

    monkeypatch.setattr(storage, "_gcs", lambda: (Client(), None))
    storage.fetch("gs://b-bronze/portal/r/a.csv", tmp_path / "x")
    assert ("blob", "portal/r/a.csv") in llamadas


def test_sin_la_variable_no_hay_restriccion_y_las_rutas_locales_no_se_afectan(solo_portal, tmp_path, monkeypatch):
    src = tmp_path / "a.txt"
    src.write_bytes(b"hola")
    storage.put(src, str(tmp_path / "fuera-de-portal" / "a.txt"))  # local: sin restricción
    assert (tmp_path / "fuera-de-portal" / "a.txt").read_bytes() == b"hola"
    monkeypatch.delenv("SECXFER_ALLOWED_PREFIX")
    monkeypatch.setattr(storage, "_gcs", lambda: (_ for _ in ()).throw(RuntimeError("llegó al cliente")))
    with pytest.raises(RuntimeError, match="llegó al cliente"):
        storage.fetch("gs://b/cualquier/cosa", tmp_path / "x")
