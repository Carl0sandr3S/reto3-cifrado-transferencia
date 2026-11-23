"""Pruebas del portal. La principal es la de extremo a extremo con el flujo REAL de securetransfer
(cifrado AES-GCM con llave local): el comercial sube, el flujo cifra/descifra/verifica, el jefe descarga
un archivo con el mismo SHA-256. Las rutas con GCS, Cloud Run y Airflow reales se prueban con dobles."""

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from werkzeug.security import generate_password_hash

from portal.app import RUN_RE, _load_users, create_app
from portal.store import AlreadyExists, GcsStore, LocalStore, NotFound, StoreError
from portal.trigger import AirflowTrigger, JobsTrigger, LocalFlowTrigger, TriggerError, job_calls
from securetransfer.keys import LocalKeyProvider, generate_local_key
from securetransfer_paths import plan_paths, receive_args, send_args, verify_args

@pytest.fixture(autouse=True)
def _aislar_logger_de_securetransfer(monkeypatch):
    """Los tests del CLI llaman a setup_logging(), que deja un handler enganchado al stderr capturado de ESE test (ya cerrado).
    El pipeline que corre en un hilo durante las pruebas del portal escribiría allí y generaría 'Logging error'. Se aísla aquí."""
    monkeypatch.setattr(logging.getLogger("securetransfer"), "handlers", [logging.NullHandler()])


USERS = {
    "maria": {"hash": generate_password_hash("clave-comercial-1"), "role": "comercial"},
    "carlos": {"hash": generate_password_hash("clave-jefe-123456"), "role": "jefe"},
}
COM, JEFE = ("maria", "clave-comercial-1"), ("carlos", "clave-jefe-123456")


def make_app(tmp_path, trigger="local"):
    store = LocalStore(tmp_path)
    trig = LocalFlowTrigger(tmp_path, LocalKeyProvider(generate_local_key())) if trigger == "local" else trigger
    app = create_app({"USERS": USERS, "STORE_OBJ": store, "TRIGGER_OBJ": trig, "TESTING": True,
                      "SESSION_COOKIE_SECURE": False})
    return app, store, trig


def client(app, creds=None):
    c = app.test_client()
    if creds:
        tok = _token(c, "/login")
        r = c.post("/login", data={"usuario": creds[0], "clave": creds[1], "csrf": tok})
        assert r.status_code == 302
    return c


def _token(c, path):
    return re.search(r'name="csrf" value="(\w+)"', c.get(path).text).group(1)


def upload(c, content=b"datos confidenciales", name="oferta.pdf"):
    import io
    return c.post("/subir", data={"csrf": _token(c, "/subir"), "archivo": (io.BytesIO(content), name)},
                  content_type="multipart/form-data")


def run_id_of(resp):
    return re.search(r"Referencia</dt>\s*<dd><code>(portal-[\w.-]+)</code>", resp.text).group(1)


# ------------------------------------------------------------- extremo a extremo


def test_e2e_comercial_sube_flujo_real_jefe_descarga_identico(tmp_path):
    app, store, trig = make_app(tmp_path)
    original = bytes(range(256)) * 2000  # binario, ~500 KB (varios chunks pequeños no hacen falta: se prueba el flujo)
    resp = upload(client(app, COM), original)
    assert hashlib.sha256(original).hexdigest() in resp.text
    run = run_id_of(resp)

    trig.wait_all(timeout=60)  # el flujo corre en segundo plano

    # En tránsito el archivo está cifrado (no contiene el texto original)
    enc = next((tmp_path / "silver" / "portal" / run).iterdir())
    assert enc.name == "oferta.pdf.enc" and original[:64] not in enc.read_bytes()

    jefe = client(app, JEFE)
    assert "oferta.pdf" in jefe.get("/archivos").text
    d = jefe.get(f"/archivos/{run}/oferta.pdf")
    assert d.status_code == 200 and d.data == original
    assert "attachment" in d.headers["Content-Disposition"]


def test_la_lista_del_jefe_no_muestra_nada_hasta_que_el_flujo_termina(tmp_path):
    app, store, _ = make_app(tmp_path, trigger=SimpleNamespace(start=lambda *a: None, wait_all=lambda **k: None))
    upload(client(app, COM))
    assert "Aún no hay archivos" in client(app, JEFE).get("/archivos").text


def test_la_lista_ignora_demos_y_corridas_ajenas_en_gold(tmp_path):
    app, store, _ = make_app(tmp_path, trigger=SimpleNamespace(start=lambda *a: None, wait_all=lambda **k: None))
    (tmp_path / "gold" / "portal" / "demo-20261121T000000Z").mkdir(parents=True)
    (tmp_path / "gold" / "portal" / "demo-20261121T000000Z" / "secreto.csv").write_bytes(b"x")
    (tmp_path / "gold" / "portal" / "manual__2026-11-21").mkdir()
    (tmp_path / "gold" / "portal" / "manual__2026-11-21" / "otro.csv").write_bytes(b"x")
    page = client(app, JEFE).get("/archivos").text
    assert "secreto.csv" not in page and "otro.csv" not in page
    assert client(app, JEFE).get("/archivos/demo-20261121T000000Z/secreto.csv").status_code == 404


# ----------------------------------------------------------------- control de acceso


def test_comercial_no_lista_ni_descarga_y_jefe_no_sube(tmp_path):
    app, *_ = make_app(tmp_path)
    com, jefe = client(app, COM), client(app, JEFE)
    run = run_id_of(upload(com))
    assert com.get("/archivos").status_code == 403
    assert com.get(f"/archivos/{run}/oferta.pdf").status_code == 403
    assert jefe.get("/subir").status_code == 403


def test_sin_sesion_redirige_a_login(tmp_path):
    app, *_ = make_app(tmp_path)
    c = app.test_client()
    for path in ("/subir", "/archivos", f"/archivos/portal-20261121T000000Z-maria-abc123/a.pdf"):
        assert c.get(path).status_code == 302


def test_login_incorrecto_y_csrf(tmp_path):
    app, *_ = make_app(tmp_path)
    c = app.test_client()
    r = c.post("/login", data={"usuario": "maria", "clave": "mala", "csrf": _token(c, "/login")})
    assert r.status_code == 200 and "incorrectos" in r.text
    com = client(app, COM)
    r = com.post("/subir", data={}, content_type="multipart/form-data")  # sin token CSRF
    assert r.status_code == 400


def test_extension_vacio_y_nombre_malicioso(tmp_path):
    app, store, _ = make_app(tmp_path, trigger=SimpleNamespace(start=lambda *a: None, wait_all=lambda **k: None))
    com = client(app, COM)
    assert "no permitido" in upload(com, b"MZ", "virus.exe").text
    assert "no esté vacío" in upload(com, b"", "a.pdf").text
    r = upload(com, b"x", "../../etc/passwd.pdf")
    run = run_id_of(r)
    saved = [p.name for p in (tmp_path / "bronze" / "portal" / run).iterdir()]
    assert saved == ["etc_passwd.pdf"]  # sin '..' ni '/': queda dentro de su propia carpeta


def test_descarga_rechaza_run_y_nombre_invalidos(tmp_path):
    app, *_ = make_app(tmp_path)
    jefe = client(app, JEFE)
    assert jefe.get("/archivos/..%2f..%2fetc/passwd").status_code == 404
    assert jefe.get("/archivos/portal-20261121T000000Z-maria-abc123/..%2fx.pdf").status_code == 404
    assert jefe.get("/archivos/portal-20261121T000000Z-maria-abc123/noexiste.pdf").status_code == 404


def test_usuarios_invalidos_se_rechazan_al_arrancar():
    # Un nombre con espacios o mayúsculas daría un run_id que el listado no reconoce; un rol desconocido no tiene pantalla.
    for bad in ({"Maria Lopez": {"hash": "x", "role": "comercial"}},
                {"maria": {"hash": "x", "role": "admin"}},
                {"maria": {"hash": "", "role": "jefe"}}):
        with pytest.raises(RuntimeError):
            _load_users({"USERS_JSON": json.dumps(bad)})


def test_si_el_flujo_no_arranca_el_comercial_lo_ve(tmp_path):
    def boom(*a):
        raise TriggerError("sin permisos")
    app, store, _ = make_app(tmp_path, trigger=SimpleNamespace(start=boom, wait_all=lambda **k: None))
    r = upload(client(app, COM))
    assert "no se pudo iniciar" in r.text and "Referencia" in r.text  # el archivo quedó en bronze, hay referencia


def test_el_identificador_de_corrida_cumple_el_formato(tmp_path):
    app, *_ = make_app(tmp_path, trigger=SimpleNamespace(start=lambda *a: None, wait_all=lambda **k: None))
    run = run_id_of(upload(client(app, COM)))
    m = RUN_RE.match(run)
    assert m and m.group(2) == "maria"
    datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ")


# ------------------------------------------------------------------- paridad con el DAG


def test_las_rutas_del_portal_coinciden_con_el_dag():
    run, obj = "portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/oferta.pdf"
    paths = plan_paths("demo-proj", run, obj)
    calls = dict(job_calls("demo-proj", run, obj))
    assert calls["st-send"] == send_args(paths)
    assert calls["st-receive"] == receive_args(paths)
    assert calls["st-verify"] == verify_args(paths)
    assert paths.out == f"gs://demo-proj-gold/portal/{obj}"  # donde el portal lee: portal/<run>/<archivo> en GOLD


# --------------------------------------------------------------------- triggers (dobles)


class FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code, self._body, self.text = status, body or {}, str(body)

    def json(self):
        return self._body


class FakeRunApi:
    """Simula la API de Cloud Run: :run devuelve una operación; consultarla la da por terminada."""

    def __init__(self, fail_job=None, polls_before_done=1):
        self.posts, self.gets, self.fail_job, self.polls = [], [], fail_job, polls_before_done
        self._count = {}

    def post(self, url, json=None, timeout=None):
        self.posts.append((url, json))
        job = url.split("/jobs/")[1].split(":")[0]
        return FakeResp(200, {"name": f"projects/p/locations/r/operations/{job}"})

    def get(self, url, timeout=None):
        self.gets.append(url)
        job = url.rsplit("/", 1)[1]
        self._count[job] = self._count.get(job, 0) + 1
        if self._count[job] <= self.polls:
            return FakeResp(200, {"done": False})
        if job == self.fail_job:
            return FakeResp(200, {"done": True, "error": {"message": "Execution failed"}})
        return FakeResp(200, {"done": True, "response": {"succeededCount": 1}})


def test_jobs_trigger_ejecuta_los_tres_jobs_en_orden_con_overrides():
    api = FakeRunApi()
    t = JobsTrigger("demo-proj", "us-east1", session=api, poll_seconds=0, sleep=lambda s: None)
    t._run("portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/a.pdf")
    jobs = [u.split("/jobs/")[1].split(":")[0] for u, _ in api.posts]
    assert jobs == ["st-send", "st-receive", "st-verify"]
    assert all(u.startswith("https://run.googleapis.com/v2/projects/demo-proj/locations/us-east1/jobs/") for u, _ in api.posts)
    body = api.posts[0][1]["overrides"]["containerOverrides"][0]
    assert body["name"] == "job" and body["args"][0] == "send"


def test_jobs_trigger_se_detiene_si_un_paso_falla():
    api = FakeRunApi(fail_job="st-receive")
    t = JobsTrigger("demo-proj", "us-east1", session=api, poll_seconds=0, sleep=lambda s: None)
    with pytest.raises(TriggerError, match="st-receive"):
        t._run("portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/a.pdf")
    assert [u.split("/jobs/")[1].split(":")[0] for u, _ in api.posts] == ["st-send", "st-receive"]  # no llegó a verify


def test_jobs_trigger_detecta_tareas_fallidas_aunque_no_haya_error():
    class Api(FakeRunApi):
        def get(self, url, timeout=None):
            return FakeResp(200, {"done": True, "response": {"failedCount": 1}})
    t = JobsTrigger("p", "r", session=Api(), poll_seconds=0, sleep=lambda s: None)
    with pytest.raises(TriggerError, match="fallida"):
        t._run("portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/a.pdf")


def test_jobs_trigger_rechaza_respuesta_http_de_error():
    class Api(FakeRunApi):
        def post(self, url, json=None, timeout=None):
            return FakeResp(403, {"error": "denied"})
    t = JobsTrigger("p", "r", session=Api(), poll_seconds=0, sleep=lambda s: None)
    with pytest.raises(TriggerError, match="403"):
        t._run("portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/a.pdf")


def test_jobs_trigger_start_corre_en_segundo_plano_y_no_lanza():
    api = FakeRunApi(fail_job="st-send")
    t = JobsTrigger("p", "r", session=api, poll_seconds=0, sleep=lambda s: None)
    t.start("portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/a.pdf")
    t.wait_all(timeout=10)  # el fallo queda en el log de auditoría, no rompe la petición web


def test_airflow_trigger_pide_el_dag_con_dag_run_id_igual_al_run():
    class Api:
        def post(self, url, json=None, timeout=None):
            self.url, self.json = url, json
            return FakeResp(200, {})
    api = Api()
    t = AirflowTrigger("https://abc-dot-us-east1.composer.googleusercontent.com/", "demo-proj", "us-east1", session=api)
    t.start("portal-20261121T000000Z-maria-abc123", "portal-20261121T000000Z-maria-abc123/a.pdf")
    assert api.url == "https://abc-dot-us-east1.composer.googleusercontent.com/api/v1/dags/securetransfer_cloud_run/dagRuns"
    assert api.json == {"dag_run_id": "portal-20261121T000000Z-maria-abc123",
                        "conf": {"project_id": "demo-proj", "region": "us-east1",
                                 "object": "portal-20261121T000000Z-maria-abc123/a.pdf"}}


def test_airflow_trigger_error_http():
    class Api:
        def post(self, url, json=None, timeout=None):
            return FakeResp(403, {})
    with pytest.raises(TriggerError, match="403"):
        AirflowTrigger("https://x", "p", "r", session=Api()).start("r", "r/a.pdf")


# ---------------------------------------------------------------------- GcsStore (doble)


class FakeBlob:
    def __init__(self, bucket, name):
        self.bucket, self.name = bucket, name
        self.size, self.updated = 0, datetime(2026, 11, 21, tzinfo=timezone.utc)

    def upload_from_string(self, data, content_type=None, if_generation_match=None):
        if if_generation_match == 0 and self.name in self.bucket.objects:
            raise type("PreconditionFailed", (Exception,), {"code": 412})()
        self.bucket.objects[self.name] = data
        self.bucket.last_args = (content_type, if_generation_match)

    def download_as_bytes(self):
        if self.name not in self.bucket.objects:
            raise type("NotFound", (Exception,), {"code": 404})()
        return self.bucket.objects[self.name]


class FakeBucket:
    def __init__(self):
        self.objects = {}

    def blob(self, name):
        return FakeBlob(self, name)


class FakeGcs:
    def __init__(self):
        self.buckets = {"o": FakeBucket(), "d": FakeBucket()}

    def bucket(self, name):
        return self.buckets[name]

    def list_blobs(self, bucket, prefix=None):
        for name, data in self.buckets[bucket].objects.items():
            if not prefix or name.startswith(prefix):
                b = FakeBlob(self.buckets[bucket], name)
                b.size = len(data)
                yield b


def test_gcs_store_crea_sin_sobrescribir_lista_y_lee_solo_en_portal():
    fake = FakeGcs()
    s = GcsStore("o", "d", client=fake)
    s.put_bronze("portal-1/a.pdf", b"x")
    assert list(fake.buckets["o"].objects) == ["portal/portal-1/a.pdf"]  # siempre dentro de portal/
    assert fake.buckets["o"].last_args == ("application/octet-stream", 0)  # if_generation_match=0
    with pytest.raises(AlreadyExists):
        s.put_bronze("portal-1/a.pdf", b"y")
    fake.buckets["d"].objects.update({"portal/portal-1/a.pdf": b"hola", "portal/demo-1/b.pdf": b"z",
                                      "otra-carpeta/portal-9/c.pdf": b"fuera"})
    assert [(e.name, e.size) for e in s.list_gold("portal-")] == [("portal-1/a.pdf", 4)]  # nombres relativos a portal/
    assert s.get_gold("portal-1/a.pdf") == b"hola"
    with pytest.raises(NotFound):
        s.get_gold("portal-1/no.pdf")
    with pytest.raises(NotFound):  # lo que está fuera de portal/ no es alcanzable aunque exista en el bucket
        s.get_gold("../otra-carpeta/portal-9/c.pdf")


def test_gcs_store_traduce_errores_de_la_api():
    class Boom(FakeGcs):
        def list_blobs(self, bucket, prefix=None):
            raise RuntimeError("403 sin permiso")
    with pytest.raises(StoreError):
        GcsStore("o", "d", client=Boom()).list_gold("portal-")


def test_local_store_no_sobrescribe_y_bloquea_path_traversal(tmp_path):
    s = LocalStore(tmp_path)
    s.put_bronze("r/a.pdf", b"1")
    with pytest.raises(AlreadyExists):
        s.put_bronze("r/a.pdf", b"2")
    with pytest.raises(StoreError):
        s.put_bronze("../fuera.pdf", b"3")
    with pytest.raises(StoreError):
        s.get_gold("../../bronze/portal/r/a.pdf")
