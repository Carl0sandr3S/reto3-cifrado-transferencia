#!/usr/bin/env python3
"""Despliegue y demo en GCP, en Python (solo biblioteca estándar; invoca la CLI `gcloud`).

    python deploy/gcp.py infra            # buckets, KMS, cuentas de servicio, permisos mínimos
    python deploy/gcp.py validate-ci      # valida las variables del workflow de GitHub Actions
    python deploy/gcp.py deploy-jobs --image IMG   # crea/actualiza los jobs con una imagen ya construida (CI)
    python deploy/gcp.py build-deploy     # construye la imagen (Cloud Build) y crea los Cloud Run Jobs
    python deploy/gcp.py demo ARCHIVO     # demo completa con verificación independiente
    python deploy/gcp.py tamper ARCHIVO   # altera 1 byte en silver: el punto B debe rechazarlo
    python deploy/gcp.py dag-import --environment ENV --location REGION   # sube el DAG a Cloud Composer
    python deploy/gcp.py grant-orchestrator --service-account EMAIL       # permite a Composer ejecutar los jobs

Opciones globales: --project, --region, --dry-run (imprime los comandos sin ejecutarlos).
Los comandos se pasan como listas (sin shell): no hay interpolación de texto en una línea de comandos.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

KEYRING = "securetransfer-ring"
KEY = "transfer-kek"
SA_SENDER = "st-sender"      # punto A: solo puede CIFRAR
SA_RECEIVER = "st-receiver"  # punto B: solo puede DESCIFRAR
JOB_SENDER = "st-send"
JOB_RECEIVER = "st-receive"
SA_VERIFIER = "st-verifier"  # solo LEE bronze y gold para comparar hashes; sin permisos sobre la llave KMS
JOB_VERIFIER = "st-verify"
CONTAINER_NAME = "job"       # nombre explícito del contenedor: el DAG de Airflow lo usa en los overrides
# Arquitectura medallion: una capa = un bucket (<proyecto>-bronze / -silver / -gold).
#   bronze: dato crudo tal como lo sube la interfaz | silver: dato cifrado con KMS | gold: recuperado y verificado
# Todo el flujo (jobs, Airflow, portal) trabaja SOLO dentro de la carpeta FLOW_FOLDER de cada capa.
# Debe coincidir con dags/securetransfer_paths.py y portal/store.py (una prueba lo comprueba).
LAYER_BRONZE, LAYER_SILVER, LAYER_GOLD = "bronze", "silver", "gold"
# Auditoría del DAG en BigQuery: una fila por ejecución. Debe coincidir con dags/securetransfer_audit.py (una prueba lo comprueba).
AUDIT_DATASET, AUDIT_TABLE = "auditoria", "ejecuciones_airflow"
AUDIT_COLUMNS = (
    ("id", "STRING"), ("nombre_dag", "STRING"), ("run_id", "STRING"), ("tipo_ejecucion", "STRING"),
    ("fecha_logica", "TIMESTAMP"), ("fecha_hora_ejecucion", "TIMESTAMP"), ("fecha_hora_fin", "TIMESTAMP"),
    ("duracion_segundos", "INT64"), ("estado_ejecucion", "STRING"), ("tarea_fallida", "STRING"), ("url_log", "STRING"),
)
ROLE_BQ_JOB_USER = "roles/bigquery.jobUser"          # lanzar consultas (proyecto); no da acceso a ningún dato
ROLE_BQ_DATA_EDITOR = "roles/bigquery.dataEditor"    # leer/escribir SOLO la tabla de auditoría (se concede sobre la tabla)
FLOW_FOLDER = "portal"
AR_REPO = "securetransfer"
APIS = [
    "run.googleapis.com", "artifactregistry.googleapis.com", "cloudbuild.googleapis.com",
    "cloudkms.googleapis.com", "storage.googleapis.com", "iam.googleapis.com",
    "logging.googleapis.com",
]

SA_EMAIL_RE = re.compile(r"^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.iam\.gserviceaccount\.com$")
COMPOSER_ENV_RE = re.compile(r"^[a-z][a-z0-9-]*$")
PROJECT_ID_RE = re.compile(r"^[a-z][a-z0-9-]{4,61}[a-z0-9]$")  # se valida porque el ID entra en sentencias SQL de BigQuery
LOCATION_RE = re.compile(r"^[a-z]+(-[a-z]+[0-9]+)?$")

# Proveedor de Workload Identity Federation: usa el NÚMERO del proyecto, no el ID (si no, GitHub falla con "Invalid value for audience").
WIF_PROVIDER_RE = re.compile(r"^projects/[0-9]+/locations/global/workloadIdentityPools/[A-Za-z0-9._-]+/providers/[A-Za-z0-9._-]+$")
CI_VARS = ("GCP_PROJECT_ID", "GCP_REGION", "GCP_KMS_KEY", "GCP_WIF_PROVIDER", "GCP_DEPLOYER_SA")


class DeployError(Exception):
    """Error controlado del despliegue: se muestra al usuario sin traza y termina con código 1."""


# gcloud


class Gcloud:
    """Envoltorio mínimo de la CLI de gcloud. Con dry_run solo imprime y registra los comandos."""

    def __init__(self, project: str, dry_run: bool = False):
        """
        Inicializa el envoltorio.

        Args:
            project: ID del proyecto de GCP que se añade a cada comando con --project.
            dry_run: Si es True, solo imprime los comandos sin ejecutarlos.
        """
        self.project = project
        self.dry_run = dry_run
        self.history: list[list[str]] = []

    def _cmd(self, args) -> list[str]:
        """
        Construye el comando completo de gcloud añadiendo --project.

        Si hay --container, --project va ANTES: gcloud exige que los flags que no son del
        contenedor se especifiquen antes de --container.

        Args:
            args: Argumentos de gcloud (sin el ejecutable); se convierten a texto.

        Returns:
            Lista de argumentos lista para subprocess, empezando por "gcloud".
        """
        parts = [str(a) for a in args]
        at = parts.index("--container") if "--container" in parts else len(parts)
        return ["gcloud", *parts[:at], "--project", self.project, *parts[at:]]

    def _log(self, cmd: list[str]) -> None:
        """
        Registra el comando en el historial y lo imprime por stderr.

        Args:
            cmd: Comando completo (lista de argumentos).

        Returns:
            None.
        """
        self.history.append(cmd)
        print("+ " + shlex.join(cmd), file=sys.stderr)

    def run(self, *args, capture: bool = False, retries: int = 1, delay: float = 5.0) -> str:
        """
        Ejecuta un comando de gcloud y falla si termina con error.

        Args:
            *args: Argumentos de gcloud (sin el ejecutable ni --project).
            capture: Si es True, captura y devuelve la salida estándar.
            retries: Número de intentos; mayor que 1 sirve para la propagación de IAM.
            delay: Segundos de espera entre intentos.

        Returns:
            La salida estándar si capture es True; cadena vacía en otro caso (y en dry-run).

        Raises:
            DeployError: Si el comando falla en todos los intentos.
        """
        cmd = self._cmd(args)
        self._log(cmd)
        if self.dry_run:
            return ""
        for attempt in range(1, retries + 1):
            proc = subprocess.run(cmd, capture_output=capture, text=True, check=False)
            if proc.returncode == 0:
                return proc.stdout if capture else ""
            if attempt < retries:
                time.sleep(delay)
        raise DeployError(f"Falló (código {proc.returncode}): {shlex.join(cmd)}")

    def bq(self, sql: str, location: str, retries: int = 1, delay: float = 5.0) -> None:
        """
        Ejecuta una sentencia SQL (DDL/DCL) con la CLI `bq`.

        Args:
            sql: Sentencia en GoogleSQL. Debe construirse solo con valores ya validados (ver audit_sql).
            location: Ubicación de BigQuery (por ejemplo us-east1).
            retries: Número de intentos (la propagación de IAM puede tardar).
            delay: Segundos entre intentos.

        Raises:
            DeployError: Si la sentencia falla en todos los intentos.
        """
        cmd = ["bq", f"--project_id={self.project}", f"--location={location}", "query", "--use_legacy_sql=false", sql]
        self._log(cmd)
        if self.dry_run:
            return
        for attempt in range(1, retries + 1):
            if subprocess.run(cmd, capture_output=False, text=True, check=False).returncode == 0:
                return
            if attempt < retries:
                time.sleep(delay)
        raise DeployError(f"Falló la sentencia de BigQuery: {sql[:120]}")

    def ok(self, *args) -> bool:
        """
        Indica si un comando termina bien (se usa con `describe` para hacer los pasos idempotentes).

        Args:
            *args: Argumentos de gcloud (sin el ejecutable ni --project).

        Returns:
            True si el comando terminó con código 0. En dry-run devuelve False para mostrar todos los pasos.
        """
        cmd = self._cmd(args)
        self._log(cmd)
        if self.dry_run:
            return False  # en dry-run se asume que nada existe, para mostrar todos los pasos
        return subprocess.run(cmd, capture_output=True, check=False).returncode == 0

    def cat_bytes(self, uri: str, byte_range: str) -> bytes:
        """
        Lee un rango de bytes de un objeto de GCS.

        Args:
            uri: URI del objeto (gs://bucket/ruta).
            byte_range: Rango en el formato de `gcloud storage cat --range`, por ejemplo "0-63".

        Returns:
            Los bytes leídos (vacío en dry-run).

        Raises:
            DeployError: Si no se puede leer el objeto.
        """
        cmd = self._cmd(["storage", "cat", uri, "--range", byte_range])
        self._log(cmd)
        if self.dry_run:
            return b""
        proc = subprocess.run(cmd, capture_output=True, check=False)
        if proc.returncode:
            raise DeployError(f"No se pudo leer {uri}")
        return proc.stdout

    def sha256_object(self, uri: str) -> str:
        """
        Calcula el SHA-256 de un objeto de GCS en streaming, independiente del código de la app.

        Args:
            uri: URI del objeto (gs://bucket/ruta).

        Returns:
            El hash SHA-256 en hexadecimal ("dry-run" en modo dry-run).

        Raises:
            DeployError: Si no se puede leer el objeto.
        """
        cmd = self._cmd(["storage", "cat", uri])
        self._log(cmd)
        if self.dry_run:
            return "dry-run"
        digest = hashlib.sha256()
        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
            while block := proc.stdout.read(1024 * 1024):
                digest.update(block)
        if proc.returncode:
            raise DeployError(f"No se pudo leer {uri}")
        return digest.hexdigest()


#  configuración


@dataclass(frozen=True)
class Config:
    """Configuración derivada del proyecto y la región: nombres de buckets, llave KMS, cuentas e imagen."""

    project_id: str
    region: str = "us-east1"
    kms_key_override: str = ""

    @property
    def bucket_bronze(self) -> str:
        """
        Nombre del bucket de la capa BRONZE (dato crudo, punto A).

        Returns:
            El nombre del bucket, sin el prefijo gs://.
        """
        return f"{self.project_id}-{LAYER_BRONZE}"

    @property
    def bucket_silver(self) -> str:
        """
        Nombre del bucket de la capa SILVER (donde queda el archivo cifrado).

        Returns:
            El nombre del bucket, sin el prefijo gs://.
        """
        return f"{self.project_id}-{LAYER_SILVER}"

    @property
    def bucket_gold(self) -> str:
        """
        Nombre del bucket de la capa GOLD (archivo recuperado y verificado, punto B).

        Returns:
            El nombre del bucket, sin el prefijo gs://.
        """
        return f"{self.project_id}-{LAYER_GOLD}"

    def flow_uri(self, bucket: str, *parts: str) -> str:
        """
        Construye un gs:// dentro de la carpeta portal/ de una capa.

        Args:
            bucket: Bucket de la capa (por ejemplo cfg.bucket_bronze).
            *parts: Tramos de ruta bajo portal/ (por ejemplo la carpeta de la ejecución y el archivo).

        Returns:
            Una URI como gs://<bucket>/portal/<parts...>.
        """
        return "gs://" + "/".join((bucket, FLOW_FOLDER, *parts))

    @property
    def kms_key(self) -> str:
        """
        Nombre completo de la llave KMS.

        Returns:
            El valor de kms_key_override si se definió; si no, la ruta de la llave por defecto del proyecto.
        """
        return self.kms_key_override or (
            f"projects/{self.project_id}/locations/{self.region}/keyRings/{KEYRING}/cryptoKeys/{KEY}"
        )

    def sa_email(self, name: str) -> str:
        """
        Construye el correo de una cuenta de servicio del proyecto.

        Args:
            name: Nombre corto de la cuenta (por ejemplo "st-sender").

        Returns:
            El correo completo nombre@proyecto.iam.gserviceaccount.com.
        """
        return f"{name}@{self.project_id}.iam.gserviceaccount.com"

    def image(self, tag: str) -> str:
        """
        Construye la ruta de la imagen en Artifact Registry.

        Args:
            tag: Etiqueta de la imagen (por ejemplo el git short sha).

        Returns:
            La ruta completa de la imagen con su etiqueta.
        """
        return f"{self.region}-docker.pkg.dev/{self.project_id}/{AR_REPO}/securetransfer:{tag}"


def resolve_project(cli_value: str | None) -> str:
    """
    Determina el ID del proyecto de GCP.

    Orden de prioridad: argumento --project, variable PROJECT_ID, variable GCP_PROJECT_ID
    y, por último, la configuración de gcloud.

    Args:
        cli_value: Valor recibido por --project (puede ser None).

    Returns:
        El ID del proyecto.

    Raises:
        DeployError: Si no se encuentra ningún proyecto definido.
    """
    project = cli_value or os.environ.get("PROJECT_ID") or os.environ.get("GCP_PROJECT_ID")
    if not project:
        proc = subprocess.run(["gcloud", "config", "get-value", "project"], capture_output=True, text=True, check=False)
        project = proc.stdout.strip() if proc.returncode == 0 else ""
    if not project or project == "(unset)":
        raise DeployError("Defina el proyecto: --project, PROJECT_ID o 'gcloud config set project ...'")
    return project


def job_args(*parts: str) -> str:
    """
    Une los argumentos de un job para `gcloud run jobs execute --args`, que usa la coma como separador.

    Args:
        *parts: Argumentos individuales que recibirá el job.

    Returns:
        Los argumentos unidos por comas.

    Raises:
        DeployError: Si algún argumento contiene una coma.
    """
    for part in parts:
        if "," in part:
            raise DeployError(f"Los argumentos de un job no pueden contener comas (separador de gcloud): {part!r}")
    return ",".join(parts)


#  comandos


def folder_condition(bucket: str) -> str:
    """
    Valor de --condition de gcloud que limita un rol a los OBJETOS de la carpeta portal/ de un bucket.

    Limitación documentada de Cloud Storage: `storage.objects.list` se concede a nivel de bucket y no se puede
    restringir por prefijo con resource.name. Por eso la condición solo acota leer/crear objetos; el listado
    se concede aparte (roles/storage.legacyBucketReader) y solo expone nombres, no contenido.

    Args:
        bucket: Nombre del bucket (sin gs://).

    Returns:
        Texto "title=...,expression=..." (sin comas dentro de la expresión, que gcloud usa como separador).
    """
    expression = f'resource.name.startsWith("projects/_/buckets/{bucket}/objects/{FLOW_FOLDER}/")'
    return f"title=solo-{FLOW_FOLDER},expression={expression}"


def bind_bucket_role(g: "Gcloud", bucket: str, member: str, role: str, folder_only: bool = True) -> None:
    """
    Asigna un rol de IAM sobre un bucket, por defecto limitado a la carpeta portal/.

    Args:
        g: Envoltorio de gcloud.
        bucket: Nombre del bucket (sin gs://).
        member: Miembro completo (por ejemplo "serviceAccount:st-sender@...").
        role: Rol de IAM a conceder.
        folder_only: True para limitar el rol a portal/ con una condición de IAM; False para el bucket completo.

    Returns:
        None.
    """
    condition = folder_condition(bucket) if folder_only else "None"
    g.run("storage", "buckets", "add-iam-policy-binding", f"gs://{bucket}",
          "--member", member, "--role", role, f"--condition={condition}", retries=3)


def cmd_infra(cfg: Config, g: Gcloud) -> None:
    """
    Crea la infraestructura (idempotente) con mínimo privilegio y separación de funciones.

    Habilita las APIs, crea los 3 buckets (bronze, silver, gold), las cuentas de servicio, el keyring y la llave KMS
    (con rotación a 90 días), asigna los permisos mínimos y crea el repositorio de imágenes.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.

    Returns:
        None.

    Raises:
        DeployError: Si algún comando de gcloud falla.
    """
    print(f">> Proyecto {cfg.project_id}  región {cfg.region}")
    g.run("services", "enable", *APIS)

    for bucket in (cfg.bucket_bronze, cfg.bucket_silver, cfg.bucket_gold):
        if not g.ok("storage", "buckets", "describe", f"gs://{bucket}"):
            g.run("storage", "buckets", "create", f"gs://{bucket}", "--location", cfg.region,
                  "--uniform-bucket-level-access", "--public-access-prevention")

    for sa in (SA_SENDER, SA_RECEIVER, SA_VERIFIER):
        if not g.ok("iam", "service-accounts", "describe", cfg.sa_email(sa)):
            g.run("iam", "service-accounts", "create", sa, "--display-name", f"securetransfer {sa}")

    if not g.ok("kms", "keyrings", "describe", KEYRING, "--location", cfg.region):
        g.run("kms", "keyrings", "create", KEYRING, "--location", cfg.region)
    if not g.ok("kms", "keys", "describe", KEY, "--keyring", KEYRING, "--location", cfg.region):
        next_rotation = (datetime.now(timezone.utc) + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        g.run("kms", "keys", "create", KEY, "--keyring", KEYRING, "--location", cfg.region,
              "--purpose", "encryption", "--rotation-period", "90d", "--next-rotation-time", next_rotation)

    def bind_bucket(bucket: str, sa: str, role: str) -> None:
        """
        Asigna un rol a una cuenta de servicio sobre la carpeta portal/ de un bucket (condición de IAM por prefijo).

        Args:
            bucket: Nombre del bucket (sin gs://).
            sa: Nombre corto de la cuenta de servicio.
            role: Rol de IAM a conceder.

        Returns:
            None.
        """
        bind_bucket_role(g, bucket, f"serviceAccount:{cfg.sa_email(sa)}", role)

    def bind_key(sa: str, role: str) -> None:
        """
        Asigna un rol a una cuenta de servicio sobre la llave KMS.

        Args:
            sa: Nombre corto de la cuenta de servicio.
            role: Rol de IAM a conceder.

        Returns:
            None.
        """
        g.run("kms", "keys", "add-iam-policy-binding", KEY, "--keyring", KEYRING, "--location", cfg.region,
              "--member", f"serviceAccount:{cfg.sa_email(sa)}", "--role", role, retries=3)

    # Todos los permisos sobre objetos están limitados a la carpeta portal/ de cada capa.
    # st-sender: lee BRONZE/portal, crea en SILVER/portal, solo CIFRA
    bind_bucket(cfg.bucket_bronze, SA_SENDER, "roles/storage.objectViewer")
    bind_bucket(cfg.bucket_silver, SA_SENDER, "roles/storage.objectCreator")
    bind_key(SA_SENDER, "roles/cloudkms.cryptoKeyEncrypter")
    # st-receiver: lee SILVER/portal, crea en GOLD/portal, solo DESCIFRA
    bind_bucket(cfg.bucket_silver, SA_RECEIVER, "roles/storage.objectViewer")
    bind_bucket(cfg.bucket_gold, SA_RECEIVER, "roles/storage.objectCreator")
    bind_key(SA_RECEIVER, "roles/cloudkms.cryptoKeyDecrypter")
    # st-verifier: solo LEE bronze/portal y gold/portal para comparar hashes (sin acceso a la llave)
    bind_bucket(cfg.bucket_bronze, SA_VERIFIER, "roles/storage.objectViewer")
    bind_bucket(cfg.bucket_gold, SA_VERIFIER, "roles/storage.objectViewer")

    if not g.ok("artifacts", "repositories", "describe", AR_REPO, "--location", cfg.region):
        g.run("artifacts", "repositories", "create", AR_REPO, "--repository-format", "docker",
              "--location", cfg.region, "--description", "Imágenes de securetransfer")
    print(f"\nListo. Llave KMS para la app:\n  SECXFER_KMS_KEY={cfg.kms_key}")


def cmd_deploy_jobs(cfg: Config, g: Gcloud, image: str) -> None:
    """
    Crea/actualiza los 3 jobs con la misma imagen y una identidad distinta cada uno.

    Orden de flags: gcloud exige que los flags que NO son del contenedor (región, cuenta, reintentos,
    timeout) vayan ANTES de --container; los del contenedor (imagen, env, memoria) van después.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        image: Ruta completa de la imagen ya construida.

    Returns:
        None.

    Raises:
        DeployError: Si el despliegue de algún job falla.
    """
    jobs = ((JOB_SENDER, SA_SENDER, True), (JOB_RECEIVER, SA_RECEIVER, True), (JOB_VERIFIER, SA_VERIFIER, False))
    for job, sa, uses_kms in jobs:
        print(f">> Desplegando job {job} (identidad {sa})")
        # SECXFER_ALLOWED_PREFIX: segunda barrera (además de IAM): el job se niega a leer/escribir fuera de portal/.
        env = f"SECXFER_LOG_FORMAT=json,SECXFER_ALLOWED_PREFIX={FLOW_FOLDER}/"
        if uses_kms:  # el verificador no toca la llave: no se le entrega ni el nombre
            env += f",SECXFER_KEY_PROVIDER=kms,SECXFER_KMS_KEY={cfg.kms_key}"
        g.run("run", "jobs", "deploy", job, "--region", cfg.region,
              "--service-account", cfg.sa_email(sa), "--max-retries", "0", "--task-timeout", "900s",
              "--container", CONTAINER_NAME, "--image", image, "--set-env-vars", env, "--memory", "1Gi")


def cmd_validate_ci(env: dict[str, str]) -> None:
    """
    Valida las variables que usa el workflow de GitHub Actions ANTES de autenticar.

    Un valor vacío o con el ID del proyecto en vez del NÚMERO en GCP_WIF_PROVIDER produce el error
    críptico 'Invalid value for "audience"'; aquí se detecta con un mensaje claro.

    Args:
        env: Variables de entorno (normalmente os.environ).

    Raises:
        DeployError: Si falta alguna variable o GCP_WIF_PROVIDER / GCP_DEPLOYER_SA tienen formato inválido.
    """
    missing = [name for name in CI_VARS if not env.get(name, "").strip()]
    if missing:
        raise DeployError("Faltan variables del repositorio (Settings > Variables): " + ", ".join(missing))
    if not WIF_PROVIDER_RE.match(env["GCP_WIF_PROVIDER"]):
        raise DeployError("GCP_WIF_PROVIDER debe ser projects/<NÚMERO>/locations/global/workloadIdentityPools/<pool>/providers/<proveedor>")
    if not SA_EMAIL_RE.match(env["GCP_DEPLOYER_SA"]):
        raise DeployError("GCP_DEPLOYER_SA debe ser un correo del tipo nombre@proyecto.iam.gserviceaccount.com")
    print("Configuración de CI válida")


def cmd_build_deploy(cfg: Config, g: Gcloud, tag: str | None) -> None:
    """
    Construye la imagen con Cloud Build y despliega los jobs con ella.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        tag: Etiqueta de la imagen. Si es None se usa el git short sha o, en su defecto, la fecha UTC.

    Returns:
        None.

    Raises:
        DeployError: Si falla la construcción o el despliegue.
    """
    tag = tag or _git_short_sha() or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    image = cfg.image(tag)
    print(f">> Construyendo imagen {image}")
    g.run("builds", "submit", "--tag", image, str(REPO_ROOT))
    cmd_deploy_jobs(cfg, g, image)


def _git_short_sha() -> str:
    """
    Obtiene el hash corto del commit actual del repositorio.

    Returns:
        El hash corto, o cadena vacía si no es un repositorio git o git falla.
    """
    proc = subprocess.run(["git", "-C", str(REPO_ROOT), "rev-parse", "--short", "HEAD"],
                          capture_output=True, text=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def _execute(cfg: Config, g: Gcloud, job: str, *parts: str) -> bool:
    """
    Ejecuta un Cloud Run Job y espera a que termine, sin lanzar excepción si falla.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        job: Nombre del job.
        *parts: Argumentos que recibirá el job.

    Returns:
        True si el job terminó correctamente; False en caso contrario.

    Raises:
        DeployError: Si algún argumento contiene una coma.
    """
    return g.ok("run", "jobs", "execute", job, "--region", cfg.region, "--wait", "--args", job_args(*parts))


def _execute_or_fail(cfg: Config, g: Gcloud, job: str, *parts: str) -> None:
    """
    Ejecuta un Cloud Run Job y espera a que termine; falla si el job falla.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        job: Nombre del job.
        *parts: Argumentos que recibirá el job.

    Returns:
        None.

    Raises:
        DeployError: Si el job falla o algún argumento contiene una coma.
    """
    g.run("run", "jobs", "execute", job, "--region", cfg.region, "--wait", "--args", job_args(*parts))


def _hexdump(data: bytes) -> str:
    """
    Formatea bytes como un volcado hexadecimal de 16 bytes por línea, con columna ASCII.

    Args:
        data: Bytes a mostrar.

    Returns:
        El volcado como texto de varias líneas (offset, bytes en hex y caracteres imprimibles).
    """
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:04x}  {chunk.hex(' '):<47}  {text}")
    return "\n".join(lines)


def _file_sha256(path: Path) -> str:
    """
    Calcula el SHA-256 de un archivo local leyéndolo por bloques.

    Args:
        path: Ruta del archivo.

    Returns:
        El hash SHA-256 en hexadecimal.
    """
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while block := fh.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def _show_logs(g: Gcloud, job: str, extra: str = "") -> None:
    """
    Imprime los últimos mensajes de log de un job desde Cloud Logging (últimos 10 minutos, máx. 8).

    Args:
        g: Envoltorio de gcloud.
        job: Nombre del job.
        extra: Condición adicional del filtro de logs, por ejemplo ' AND severity>=ERROR'.

    Returns:
        None.

    Raises:
        DeployError: Si falla la consulta de logs.
    """
    out = g.run("logging", "read",
                f'resource.type="cloud_run_job" AND resource.labels.job_name="{job}"{extra}',
                "--limit", "8", "--freshness", "10m", "--format", "value(jsonPayload.message)", capture=True)
    print(f"-- {job}\n{out.strip()}")


def cmd_demo(cfg: Config, g: Gcloud, file: Path) -> bool:
    """
    Ejecuta la demo A -> silver -> B con CUALQUIER archivo, sin tocar el código, y verificación independiente.

    Sube el archivo a BRONZE/portal, lo cifra a SILVER (job sender), lo descifra y entrega en GOLD (job receiver)
    y compara los SHA-256 del original y del recuperado.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        file: Archivo local a transferir.

    Returns:
        True si el archivo recuperado es idéntico al original; False en caso contrario.

    Raises:
        DeployError: Si el archivo no existe o falla algún paso.
    """
    if not file.is_file() and not g.dry_run:
        raise DeployError(f"No existe el archivo {file}")
    name = file.name
    run = "demo-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")  # carpeta única: se puede repetir
    src = cfg.flow_uri(cfg.bucket_bronze, run, name)
    enc = cfg.flow_uri(cfg.bucket_silver, run, f"{name}.enc")
    out = cfg.flow_uri(cfg.bucket_gold, run, name)

    print("== 1) Original ==")
    print(f"{_file_sha256(file) if file.is_file() else 'dry-run'}  {file}")
    print("\n== 2) Subiendo a BRONZE/portal (punto A) ==")
    g.run("storage", "cp", str(file), src)
    print(f"\n== 3) Job {JOB_SENDER}: cifrar con KMS y dejar en SILVER ==")
    _execute_or_fail(cfg, g, JOB_SENDER, "send", "--source", src, "--destination", cfg.flow_uri(cfg.bucket_silver, run) + "/")
    print("\n== Objeto cifrado en SILVER (primeros 64 bytes: firma + inicio de cabecera) ==")
    g.run("storage", "ls", "-l", enc)
    print(_hexdump(g.cat_bytes(enc, "0-63")))
    print(f"\n== 4) Job {JOB_RECEIVER}: descifrar, verificar y entregar en GOLD (punto B) ==")
    _execute_or_fail(cfg, g, JOB_RECEIVER, "receive", "--source", enc, "--destination", cfg.flow_uri(cfg.bucket_gold, run) + "/")

    print("\n== 5) Verificación independiente (hashlib; no usa el código de la app) ==")
    h_orig, h_rec = g.sha256_object(src), g.sha256_object(out)
    print(f"bronze     {src}\n  {h_orig}\nrecuperado {out}\n  {h_rec}")
    same = h_orig == h_rec
    print("RESULTADO: IDÉNTICOS" if same else "RESULTADO: DIFERENTES", file=sys.stdout if same else sys.stderr)

    print("\n== Logs estructurados (Cloud Logging) ==")
    for job in (JOB_SENDER, JOB_RECEIVER):
        _show_logs(g, job)
    return same


def cmd_tamper(cfg: Config, g: Gcloud, file: Path) -> bool:
    """
    Altera 1 byte del cifrado en SILVER: el punto B debe fallar y no publicar nada en GOLD.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        file: Archivo local que se envía y cuyo cifrado se altera.

    Returns:
        True si el job receptor rechazó el archivo alterado y GOLD quedó vacío; False en caso contrario.

    Raises:
        DeployError: Si falla algún paso previo a la alteración (subida, cifrado o descarga).
    """
    name = file.name
    run = "tamper-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    src = cfg.flow_uri(cfg.bucket_bronze, run, name)
    enc = cfg.flow_uri(cfg.bucket_silver, run, f"{name}.enc")
    bad = cfg.flow_uri(cfg.bucket_silver, run, f"{name}.TAMPERED.enc")

    g.run("storage", "cp", str(file), src)
    _execute_or_fail(cfg, g, JOB_SENDER, "send", "--source", src, "--destination", cfg.flow_uri(cfg.bucket_silver, run) + "/")

    print(">> Alterando 1 byte del cifrado (como lo haría un atacante o un fallo de red)")
    with tempfile.TemporaryDirectory(prefix="st-tamper-") as tmp:  # se elimina solo, sin rm
        local = Path(tmp) / "x.enc"
        g.run("storage", "cp", enc, str(local))
        if not g.dry_run:
            data = bytearray(local.read_bytes())
            data[-20] ^= 0x01
            local.write_bytes(bytes(data))
        g.run("storage", "cp", str(local), bad)

    print(">> El punto B debe FALLAR (código de salida 3 = integridad)")
    if _execute(cfg, g, JOB_RECEIVER, "receive", "--source", bad, "--destination", cfg.flow_uri(cfg.bucket_gold, run) + "/") and not g.dry_run:
        print("ERROR: el job aceptó un archivo alterado", file=sys.stderr)
        return False
    print(">> Fallo esperado. Comprobando que NO se publicó nada en GOLD:")
    listing = subprocess.run(g._cmd(["storage", "ls", cfg.flow_uri(cfg.bucket_gold, run) + "/"]),
                             capture_output=True, text=True, check=False) if not g.dry_run else None
    if listing is not None and listing.returncode == 0 and listing.stdout.strip():
        print("ERROR: hay objetos en gold", file=sys.stderr)
        return False
    print("   GOLD vacío para esta ejecución")
    _show_logs(g, JOB_RECEIVER, " AND severity>=ERROR")
    return True


def cmd_grant_orchestrator(cfg: Config, g: Gcloud, service_account: str) -> None:
    """
    Permite que la cuenta de Cloud Composer EJECUTE los jobs (con overrides: el DAG pasa argumentos).

    Solo se concede ejecutar, job por job: Composer no recibe permisos sobre buckets ni sobre la llave KMS.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        service_account: Correo de la cuenta de servicio del entorno de Composer.

    Returns:
        None.

    Raises:
        DeployError: Si el correo no tiene el formato esperado o falla algún comando.
    """
    if not SA_EMAIL_RE.match(service_account):
        raise DeployError("--service-account debe ser un correo del tipo nombre@proyecto.iam.gserviceaccount.com")
    for job in (JOB_SENDER, JOB_RECEIVER, JOB_VERIFIER):
        g.run("run", "jobs", "add-iam-policy-binding", job, "--region", cfg.region,
              "--member", f"serviceAccount:{service_account}", "--role", "roles/run.jobsExecutorWithOverrides", retries=3)


def audit_sql(project: str, location: str, member: str | None = None) -> list[str]:
    """
    Sentencias SQL de la tabla de auditoría: crear dataset y tabla (idempotente) y, opcionalmente, dar acceso a una cuenta.

    Args:
        project: ID del proyecto (validado: entra en el texto SQL).
        location: Ubicación del dataset (la misma región de los jobs).
        member: Correo de una cuenta de servicio a la que dar roles/bigquery.dataEditor SOLO sobre la tabla; None para omitir.

    Returns:
        Lista de sentencias, en el orden en que deben ejecutarse.

    Raises:
        DeployError: Si el proyecto, la ubicación o la cuenta no tienen el formato esperado.
    """
    if not PROJECT_ID_RE.match(project):
        raise DeployError(f"ID de proyecto inválido para BigQuery: {project!r}")
    if not LOCATION_RE.match(location):
        raise DeployError(f"Ubicación de BigQuery inválida: {location!r}")
    table = f"`{project}.{AUDIT_DATASET}.{AUDIT_TABLE}`"
    columns = ",\n  ".join(f"{name} {kind}" for name, kind in AUDIT_COLUMNS)
    sql = [
        f'CREATE SCHEMA IF NOT EXISTS `{project}.{AUDIT_DATASET}` OPTIONS (location = "{location}")',
        f"CREATE TABLE IF NOT EXISTS {table} (\n  {columns}\n)",
    ]
    if member is not None:
        if not SA_EMAIL_RE.match(member):
            raise DeployError(f"Cuenta de servicio inválida: {member!r}")
        sql.append(f'GRANT `{ROLE_BQ_DATA_EDITOR}` ON TABLE {table} TO "serviceAccount:{member}"')
    return sql


def cmd_audit_table(cfg: Config, g: Gcloud, service_account: str | None = None) -> None:
    """
    Crea (si no existen) el dataset `auditoria` y la tabla `ejecuciones_airflow`, y da acceso a la cuenta de Airflow.

    Mínimo privilegio: la cuenta recibe jobUser en el proyecto (solo puede lanzar consultas) y dataEditor SOLO sobre
    esta tabla; no ve ningún otro dato de BigQuery. Es idempotente: si la tabla ya existe (por ejemplo la creó otro
    despliegue con las mismas columnas) no se toca.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        service_account: Cuenta del entorno de Airflow; None para solo crear la tabla.

    Raises:
        DeployError: Si algún valor es inválido o falla un comando.
    """
    statements = audit_sql(cfg.project_id, cfg.region, service_account)
    g.run("services", "enable", "bigquery.googleapis.com")
    for sql in statements[:2]:
        g.bq(sql, cfg.region)
    if service_account is not None:
        g.run("projects", "add-iam-policy-binding", cfg.project_id, "--member", f"serviceAccount:{service_account}",
              "--role", ROLE_BQ_JOB_USER, "--condition=None", retries=3)
        g.bq(statements[2], cfg.region, retries=3)  # la cuenta recién creada puede tardar en propagarse


def cmd_dag_import(cfg: Config, g: Gcloud, environment: str, location: str) -> None:
    """
    Sube el DAG y su módulo auxiliar a la carpeta de DAGs del entorno de Cloud Composer.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno de Composer.
        location: Región del entorno de Composer.

    Returns:
        None.

    Raises:
        DeployError: Si el nombre del entorno no es válido o falla la importación.
    """
    if not COMPOSER_ENV_RE.match(environment):
        raise DeployError("--environment debe ser el nombre del entorno de Composer (minúsculas, dígitos y guiones)")
    for name in ("securetransfer_paths.py", "securetransfer_audit.py", "securetransfer_dag.py"):  # primero los módulos que el DAG importa
        g.run("composer", "environments", "storage", "dags", "import", "--environment", environment,
              "--location", location, "--source", str(REPO_ROOT / "dags" / name))


# CLI


def build_parser() -> argparse.ArgumentParser:
    """
    Construye el analizador de argumentos de la línea de comandos con todos los subcomandos.

    Returns:
        El ArgumentParser configurado.
    """
    p = argparse.ArgumentParser(prog="deploy/gcp.py", description="Despliegue y demo en GCP (Python).")
    p.add_argument("--project", help="ID del proyecto (o PROJECT_ID / gcloud config)")
    p.add_argument("--region", default=os.environ.get("REGION") or os.environ.get("GCP_REGION") or "us-east1")
    p.add_argument("--dry-run", action="store_true", help="imprime los comandos de gcloud sin ejecutarlos")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("infra", help="crea buckets, KMS, cuentas de servicio y permisos")
    b = sub.add_parser("build-deploy", help="construye la imagen y crea los Cloud Run Jobs")
    b.add_argument("--tag", help="etiqueta de la imagen (def.: git short sha)")
    for name, text in (("demo", "demo end-to-end con un archivo"), ("tamper", "demo de alteración en silver")):
        s = sub.add_parser(name, help=text)
        s.add_argument("file", type=Path)
    sub.add_parser("validate-ci", help="valida las variables del workflow de CI (sin tocar la nube)")
    dj = sub.add_parser("deploy-jobs", help="crea/actualiza los Cloud Run Jobs con una imagen ya construida (lo usa el CI)")
    dj.add_argument("--image", required=True, help="ruta completa de la imagen en Artifact Registry")
    o = sub.add_parser("grant-orchestrator", help="permite a la cuenta de Composer ejecutar los jobs")
    o.add_argument("--service-account", required=True, help="cuenta de servicio del entorno de Composer")
    i = sub.add_parser("dag-import", help="sube el DAG de Airflow a Cloud Composer")
    i.add_argument("--environment", required=True, help="nombre del entorno de Composer")
    i.add_argument("--location", help="región del entorno (def.: --region)")
    return p


def main(argv: list[str] | None = None) -> int:
    """
    Punto de entrada: interpreta los argumentos y ejecuta el subcomando elegido.

    Args:
        argv: Lista de argumentos; si es None se usan los de sys.argv.

    Returns:
        Código de salida: 0 si todo salió bien, 1 si hubo error o la verificación falló,
        130 si el usuario interrumpió con Ctrl+C.
    """
    args = build_parser().parse_args(argv)
    try:
        if args.command == "validate-ci":  # no necesita gcloud ni proyecto: solo revisa variables
            cmd_validate_ci(dict(os.environ))
            return 0
        project = resolve_project(args.project)
        cfg = Config(project_id=project, region=args.region, kms_key_override=os.environ.get("GCP_KMS_KEY", ""))
        g = Gcloud(project, dry_run=args.dry_run)
        if args.command == "infra":
            cmd_infra(cfg, g)
        elif args.command == "build-deploy":
            cmd_build_deploy(cfg, g, args.tag)
        elif args.command == "deploy-jobs":
            cmd_deploy_jobs(cfg, g, args.image)
        elif args.command == "demo":
            return 0 if cmd_demo(cfg, g, args.file) else 1
        elif args.command == "tamper":
            return 0 if cmd_tamper(cfg, g, args.file) else 1
        elif args.command == "grant-orchestrator":
            cmd_grant_orchestrator(cfg, g, args.service_account)
        elif args.command == "dag-import":
            cmd_dag_import(cfg, g, args.environment, args.location or cfg.region)
        return 0
    except DeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())