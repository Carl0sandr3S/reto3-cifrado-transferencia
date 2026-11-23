"""Cómo el portal pone en marcha el flujo securetransfer cuando llega un archivo a BRONZE.

  jobs     Ejecuta st-send -> st-receive -> st-verify directamente (API de Cloud Run). No necesita Composer.
  airflow  Dispara el DAG `securetransfer_cloud_run` por la API REST de Airflow (Composer). Es la opción con
           historial, reintentos y orquestación; usa los mismos tres jobs.
  local    Solo desarrollo: ejecuta securetransfer.pipeline (llave local) sobre carpetas locales.

En los tres casos el portal NO cifra nada ni ve la llave: solo pide que el flujo corra.
Las rutas son las mismas que calcula dags/securetransfer_paths.py (una prueba comprueba que no se desvíen).
"""

from __future__ import annotations

import logging
import threading
import time
from concurrent.futures import Future, ThreadPoolExecutor, wait
from pathlib import Path

from .audit import audit

log = logging.getLogger("portal")

JOB_SENDER, JOB_RECEIVER, JOB_VERIFIER = "st-send", "st-receive", "st-verify"
FLOW_FOLDER = "portal"  # carpeta de cada capa (bronze/silver/gold) donde vive todo lo de la interfaz
CONTAINER_NAME = "job"  # nombre del contenedor con el que deploy/gcp.py crea los jobs
DEFAULT_DAG_ID = "securetransfer_cloud_run"
CLOUD_PLATFORM_SCOPE = "https://www.googleapis.com/auth/cloud-platform"


class TriggerError(Exception):
    """No se pudo poner en marcha el flujo."""


def authorized_session():
    """Sesión HTTP con las credenciales de la cuenta de servicio de Cloud Run (se crea al usarla)."""
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
    except ImportError as exc:
        raise TriggerError("Falta la dependencia google-auth") from exc
    credentials, _ = google.auth.default(scopes=[CLOUD_PLATFORM_SCOPE])
    return AuthorizedSession(credentials)


def job_calls(project: str, run_id: str, obj: str) -> list[tuple[str, list[str]]]:
    """Los tres pasos del flujo con sus argumentos. Misma lógica que plan_paths() del DAG.
    `obj` es relativo a bronze/portal/ (p. ej. '<run>/<archivo>'); el flujo solo toca la carpeta portal/ de cada capa."""
    name = obj.rsplit("/", 1)[-1]
    f = FLOW_FOLDER
    src = f"gs://{project}-bronze/{f}/{obj}"
    transit_dir = f"gs://{project}-silver/{f}/{run_id}/"
    enc = f"{transit_dir}{name}.enc"
    out_dir = f"gs://{project}-gold/{f}/{run_id}/"
    out = f"{out_dir}{name}"
    return [
        (JOB_SENDER, ["send", "--source", src, "--destination", transit_dir]),
        (JOB_RECEIVER, ["receive", "--source", enc, "--destination", out_dir]),
        (JOB_VERIFIER, ["verify", "--original", src, "--recovered", out]),
    ]


class _Background:
    """Ejecuta el flujo fuera de la petición web para que la pantalla responda al instante."""

    def __init__(self):
        self._pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="flow")
        self._futures: set[Future] = set()
        self._lock = threading.Lock()

    def start(self, run_id: str, obj: str) -> None:
        fut = self._pool.submit(self._safe_run, run_id, obj)
        with self._lock:
            self._futures.add(fut)
        fut.add_done_callback(lambda f: self._futures.discard(f))

    def wait_all(self, timeout: float | None = None) -> None:
        """Espera a que terminen los flujos en curso (útil en pruebas)."""
        with self._lock:
            pending = list(self._futures)
        wait(pending, timeout=timeout)

    def _safe_run(self, run_id: str, obj: str) -> None:
        try:
            self._run(run_id, obj)
            audit("flow_done", run_id=run_id)
        except Exception as exc:  # noqa: BLE001 - un hilo no debe morir en silencio
            audit("flow_failed", run_id=run_id, error=f"{type(exc).__name__}: {exc}"[:300])

    def _run(self, run_id: str, obj: str) -> None:  # pragma: no cover - lo define cada subclase
        raise NotImplementedError


class JobsTrigger(_Background):
    """Ejecuta los tres Cloud Run Jobs en orden y espera a cada uno. Si uno falla, no corre el siguiente."""

    API = "https://run.googleapis.com/v2"

    def __init__(self, project: str, region: str, session=None, poll_seconds: float = 5.0,
                 timeout_seconds: float = 900.0, sleep=time.sleep):
        super().__init__()
        self.project, self.region = project, region
        self._session = session
        self.poll_seconds, self.timeout_seconds, self._sleep = poll_seconds, timeout_seconds, sleep

    @property
    def session(self):
        if self._session is None:
            self._session = authorized_session()
        return self._session

    def _run(self, run_id: str, obj: str) -> None:
        for job, args in job_calls(self.project, run_id, obj):
            audit("flow_step_start", run_id=run_id, job=job)
            self._run_job(job, args)
            audit("flow_step_ok", run_id=run_id, job=job)

    def _run_job(self, job: str, args: list[str]) -> None:
        url = f"{self.API}/projects/{self.project}/locations/{self.region}/jobs/{job}:run"
        body = {"overrides": {"containerOverrides": [{"name": CONTAINER_NAME, "args": args}], "taskCount": 1}}
        resp = self.session.post(url, json=body, timeout=30)
        if resp.status_code != 200:
            raise TriggerError(f"{job}: la API de Cloud Run respondió {resp.status_code}: {resp.text[:200]}")
        operation = resp.json()["name"]
        deadline = time.monotonic() + self.timeout_seconds
        while True:
            op = self.session.get(f"{self.API}/{operation}", timeout=30)
            if op.status_code != 200:
                raise TriggerError(f"{job}: no se pudo consultar la operación ({op.status_code})")
            data = op.json()
            if data.get("done"):
                failed = data.get("response", {}).get("failedCount", 0)
                if "error" in data or failed:
                    message = data.get("error", {}).get("message", f"{failed} tarea(s) fallida(s)")
                    raise TriggerError(f"{job} falló: {message}"[:300])
                return
            if time.monotonic() > deadline:
                raise TriggerError(f"{job}: tiempo de espera agotado")
            self._sleep(self.poll_seconds)


class AirflowTrigger:
    """Dispara el DAG por la API REST de Airflow. El DAG se encarga de esperar, encadenar y reintentar.

    Se fija `dag_run_id = run_id` para que el DAG deje el resultado en gold/portal/<run_id>/<archivo>,
    que es donde el portal lo busca (el DAG usa el run_id como carpeta).
    """

    def __init__(self, airflow_uri: str, project: str, region: str, dag_id: str = DEFAULT_DAG_ID, session=None):
        self.base = airflow_uri.rstrip("/")
        self.project, self.region, self.dag_id = project, region, dag_id
        self._session = session

    @property
    def session(self):
        if self._session is None:
            self._session = authorized_session()
        return self._session

    def start(self, run_id: str, obj: str) -> None:
        body = {"dag_run_id": run_id, "conf": {"project_id": self.project, "region": self.region, "object": obj}}
        resp = self.session.post(f"{self.base}/api/v1/dags/{self.dag_id}/dagRuns", json=body, timeout=30)
        if resp.status_code not in (200, 201):
            raise TriggerError(f"Airflow respondió {resp.status_code}: {resp.text[:200]}")

    def wait_all(self, timeout: float | None = None) -> None:
        """Sin trabajo local pendiente: Airflow ejecuta el flujo."""


class LocalFlowTrigger(_Background):
    """Solo desarrollo: corre el flujo real (securetransfer.pipeline) con llave local sobre carpetas locales
    que replican los buckets: <root>/bronze/portal, <root>/silver/portal y <root>/gold/portal."""

    def __init__(self, root: str | Path, provider):
        super().__init__()
        self.root, self.provider = Path(root), provider

    def _run(self, run_id: str, obj: str) -> None:
        from securetransfer import pipeline  # solo existe en el repositorio, no en la imagen del portal

        src = str(self.root / "bronze" / FLOW_FOLDER / obj)
        sent = pipeline.send(src, f"{self.root}/silver/{FLOW_FOLDER}/{run_id}/", self.provider)
        got = pipeline.receive(sent["destination"], f"{self.root}/gold/{FLOW_FOLDER}/{run_id}/", self.provider)
        check = pipeline.verify(src, got["destination"])
        if not check["match"]:
            raise TriggerError("verify: el archivo recuperado NO coincide con el original")


class NoopTrigger:
    """No dispara nada (el archivo solo queda en bronze). Útil para probar la subida aislada."""

    def start(self, run_id: str, obj: str) -> None:
        audit("flow_not_triggered", run_id=run_id)

    def wait_all(self, timeout: float | None = None) -> None:
        pass
