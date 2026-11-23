#!/usr/bin/env python3
"""Despliegue del PORTAL web en Cloud Run, conectado al flujo securetransfer (solo biblioteca estándar; invoca `gcloud`).

    python deploy/portal.py secrets --users-file users.json   # sube usuarios (hash) y la llave de sesión a Secret Manager
    python deploy/portal.py infra   [--trigger jobs|airflow]  # cuenta st-portal con permisos mínimos
    python deploy/portal.py deploy  [--trigger jobs|airflow]  # construye la imagen y publica el servicio
    python deploy/portal.py up      [--trigger jobs|airflow]  # infra + deploy
    python deploy/portal.py url                               # imprime la URL del portal

Requisitos previos: `python deploy/gcp.py infra` y `python deploy/gcp.py build-deploy` (buckets, KMS y los 3 jobs).
Con `--trigger airflow` además: el entorno de Composer en RUNNING con el DAG importado (deploy/composer.py).

Opciones globales: --project, --region, --dry-run (imprime los comandos sin ejecutarlos).
Los comandos se pasan como listas (sin shell): no hay interpolación de texto en una línea de comandos.
"""

from __future__ import annotations

import argparse
import json
import re
import secrets
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # permite `python deploy/portal.py` desde la raíz

from deploy.composer import DEFAULT_ENVIRONMENT, ROLE_LIST_BUCKET, _check_environment  # noqa: E402  (después de ajustar sys.path)
from deploy.gcp import (  # noqa: E402
    AR_REPO,
    REPO_ROOT,
    Config,
    DeployError,
    Gcloud,
    bind_bucket_role,
    cmd_grant_orchestrator,
    resolve_project,
)

SERVICE = "portal-archivos"
SA_PORTAL = "st-portal"  # sube a BRONZE/portal (solo crear), lee GOLD/portal (solo leer) y pone en marcha el flujo. Sin KMS, sin SILVER.
SECRET_KEY_NAME = "portal-secret-key"  # firma de sesiones: debe ser estable entre reinicios
SECRET_USERS_NAME = "portal-users"     # usuarios con clave en hash (no contiene claves)
TRIGGERS = ("jobs", "airflow")
PORTAL_APIS = [
    "run.googleapis.com", "secretmanager.googleapis.com", "cloudbuild.googleapis.com",
    "artifactregistry.googleapis.com", "storage.googleapis.com", "iam.googleapis.com", "logging.googleapis.com",
]
ROLE_BRONZE = "roles/storage.objectCreator"   # crea objetos en bronze/portal; no puede leer ni listar lo que subió
ROLE_GOLD = "roles/storage.objectViewer"      # lee lo recuperado en gold/portal (condición por prefijo); no puede escribir
ROLE_RUN_VIEWER = "roles/run.viewer"          # run.operations.get: necesario para esperar a que termine cada job
ROLE_COMPOSER_USER = "roles/composer.user"    # llamar a Airflow desde el portal. VERIFICAR en su entorno (ver README)
ROLE_SECRET = "roles/secretmanager.secretAccessor"
AIRFLOW_URI_RE = re.compile(r"^https://[A-Za-z0-9.-]+(/[A-Za-z0-9._~/-]*)?$")
TAG_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def portal_email(cfg: Config) -> str:
    """Correo de la cuenta de servicio del portal."""
    return cfg.sa_email(SA_PORTAL)


def _check_trigger(trigger: str) -> None:
    if trigger not in TRIGGERS:
        raise DeployError(f"--trigger debe ser uno de: {', '.join(TRIGGERS)}")


def _run_with_stdin(g: Gcloud, args: list[str], data: str) -> None:
    """Ejecuta gcloud pasando el valor por stdin: el secreto no aparece en la lista de procesos ni en el historial."""
    cmd = g._cmd(args)
    g._log(cmd)
    if g.dry_run:
        return
    proc = subprocess.run(cmd, input=data, text=True, capture_output=True, check=False)
    if proc.returncode:
        raise DeployError(f"Falló (código {proc.returncode}): {shlex.join(cmd)}\n{proc.stderr.strip()}")


# Comandos


def cmd_secrets(cfg: Config, g: Gcloud, users_file: Path) -> None:
    """
    Crea (o actualiza) los dos secretos del portal en Secret Manager.

    - portal-secret-key: llave aleatoria para firmar sesiones. Solo se crea si no existe (no se rota sola).
    - portal-users: contenido de users.json (usuarios con clave en hash). Si ya existe, se agrega una versión nueva.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        users_file: Archivo generado por `python -m portal.manage_users`.

    Raises:
        DeployError: Si el archivo de usuarios no existe, no es JSON válido o está vacío.
    """
    if g.dry_run and not users_file.is_file():
        users_json = "{}"
    else:
        if not users_file.is_file():
            raise DeployError(f"No existe {users_file}; créelo con: python -m portal.manage_users add <usuario> <comercial|jefe>")
        try:
            users = json.loads(users_file.read_text())
        except ValueError as exc:
            raise DeployError(f"{users_file} no es JSON válido") from exc
        roles = {u.get("role") for u in users.values()} if isinstance(users, dict) else set()
        if not {"comercial", "jefe"} <= roles:
            raise DeployError("users.json debe tener al menos un usuario 'comercial' y uno 'jefe'")
        users_json = json.dumps(users)
    g.run("services", "enable", "secretmanager.googleapis.com")
    if not g.ok("secrets", "describe", SECRET_KEY_NAME):
        _run_with_stdin(g, ["secrets", "create", SECRET_KEY_NAME, "--replication-policy", "automatic", "--data-file", "-"],
                        secrets.token_hex(32))
    if g.ok("secrets", "describe", SECRET_USERS_NAME):
        _run_with_stdin(g, ["secrets", "versions", "add", SECRET_USERS_NAME, "--data-file", "-"], users_json)
    else:
        _run_with_stdin(g, ["secrets", "create", SECRET_USERS_NAME, "--replication-policy", "automatic", "--data-file", "-"],
                        users_json)


def cmd_infra(cfg: Config, g: Gcloud, trigger: str) -> None:
    """
    Crea la cuenta del portal con el mínimo de permisos.

    - BRONZE: solo crear objetos en portal/ (el portal no puede leer lo que sube).
    - GOLD: solo leer objetos de portal/ y listar el bucket (el listado no se puede acotar por prefijo con IAM).
    - Sin acceso a SILVER ni a la llave KMS: el portal no puede descifrar nada por su cuenta.
    - Para poner en marcha el flujo:
        jobs    -> ejecutar los 3 Cloud Run Jobs (con overrides) y leer sus operaciones (run.viewer).
        airflow -> usar la API de Airflow de Composer.
    - Leer los dos secretos.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        trigger: "jobs" o "airflow".

    Raises:
        DeployError: Si el trigger es inválido, faltan los secretos o falla un comando de gcloud.
    """
    _check_trigger(trigger)
    sa = portal_email(cfg)
    member = f"serviceAccount:{sa}"
    print(f">> Proyecto {cfg.project_id}  región {cfg.region}  portal={sa}  trigger={trigger}")
    g.run("services", "enable", *PORTAL_APIS)
    if not g.ok("iam", "service-accounts", "describe", sa):
        g.run("iam", "service-accounts", "create", SA_PORTAL, "--display-name", "securetransfer portal web")

    bind_bucket_role(g, cfg.bucket_bronze, member, ROLE_BRONZE)                       # crear, solo en portal/
    bind_bucket_role(g, cfg.bucket_gold, member, ROLE_GOLD)                           # leer, solo en portal/
    bind_bucket_role(g, cfg.bucket_gold, member, ROLE_LIST_BUCKET, folder_only=False)  # listar nombres (bucket completo)

    if trigger == "jobs":
        cmd_grant_orchestrator(cfg, g, sa)  # roles/run.jobsExecutorWithOverrides sobre cada job (no sobre el proyecto)
        # Las operaciones de Cloud Run pertenecen a la ubicación, no al job: este rol de solo lectura va a nivel de proyecto
        # (mismo motivo que para st-orchestrator en deploy/composer.py).
        g.run("projects", "add-iam-policy-binding", cfg.project_id, "--member", member,
              "--role", ROLE_RUN_VIEWER, "--condition=None", retries=3)
    else:
        g.run("projects", "add-iam-policy-binding", cfg.project_id, "--member", member,
              "--role", ROLE_COMPOSER_USER, "--condition=None", retries=3)

    for name in (SECRET_KEY_NAME, SECRET_USERS_NAME):
        if not g.ok("secrets", "describe", name) and not g.dry_run:
            raise DeployError(f"Falta el secreto {name}: ejecute primero  python deploy/portal.py secrets --users-file users.json")
        g.run("secrets", "add-iam-policy-binding", name, "--member", member, "--role", ROLE_SECRET, retries=3)


def airflow_uri(cfg: Config, g: Gcloud, environment: str) -> str:
    """
    Obtiene la URL de la interfaz/API de Airflow del entorno de Composer.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno de Composer.

    Returns:
        La URL (https://...); un marcador en dry-run.

    Raises:
        DeployError: Si el entorno no existe o la URL no tiene el formato esperado.
    """
    _check_environment(environment)
    out = g.run("composer", "environments", "describe", environment, "--location", cfg.region,
                "--format", "value(config.airflowUri)", capture=True).strip()
    if g.dry_run:
        return "https://AIRFLOW-URI"
    if not AIRFLOW_URI_RE.match(out):
        raise DeployError(f"URL de Airflow inesperada: {out!r}")
    return out


def cmd_deploy(cfg: Config, g: Gcloud, trigger: str, airflow: str | None = None, tag: str | None = None,
               service: str = SERVICE, environment: str = DEFAULT_ENVIRONMENT, public: bool = True) -> None:
    """
    Construye la imagen del portal con Cloud Build y publica el servicio en Cloud Run.

    Modo jobs: una sola instancia siempre encendida y con CPU permanente, porque el flujo se ejecuta en un hilo
    de fondo mientras espera a cada job. Modo airflow: sin estado local, así que escala con normalidad.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        trigger: "jobs" o "airflow".
        airflow: URL de Airflow (si es None y el modo es airflow, se consulta a Composer).
        tag: Etiqueta de la imagen (def.: fecha UTC).
        service: Nombre del servicio de Cloud Run.
        environment: Entorno de Composer (solo modo airflow).
        public: Si es True, la URL admite llamadas sin identidad de Google (el login de la app protege el acceso).

    Raises:
        DeployError: Si algún dato es inválido o falla un comando de gcloud.
    """
    _check_trigger(trigger)
    tag = tag or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    if not TAG_RE.match(tag):
        raise DeployError("--tag inválida")
    if not re.match(r"^[a-z][a-z0-9-]{0,62}$", service):
        raise DeployError("Nombre de servicio inválido")
    env = f"PORTAL_STORE=gcs,PORTAL_TRIGGER={trigger},PROJECT_ID={cfg.project_id},REGION={cfg.region},COOKIE_SECURE=1"
    if trigger == "airflow":
        airflow = airflow or airflow_uri(cfg, g, environment)
        if not AIRFLOW_URI_RE.match(airflow):
            raise DeployError("--airflow-uri debe ser una URL https://...")
        env += f",AIRFLOW_URI={airflow}"
        scaling = ["--max-instances", "3"]
    else:
        scaling = ["--min-instances", "1", "--max-instances", "1", "--no-cpu-throttling"]

    image = cfg.image(tag).replace("/securetransfer:", f"/{SERVICE}:")  # mismo repositorio de Artifact Registry
    print(f">> Construyendo imagen {image}")
    g.run("builds", "submit", "--tag", image, str(REPO_ROOT / "portal"))
    print(f">> Publicando {service} (trigger={trigger})")
    g.run("run", "deploy", service, "--region", cfg.region, "--image", image,
          "--service-account", portal_email(cfg), "--memory", "512Mi", *scaling,
          "--set-env-vars", env,
          "--set-secrets", f"SECRET_KEY={SECRET_KEY_NAME}:latest,USERS_JSON={SECRET_USERS_NAME}:latest",
          "--allow-unauthenticated" if public else "--no-allow-unauthenticated")
    cmd_url(cfg, g, service)


def cmd_url(cfg: Config, g: Gcloud, service: str = SERVICE) -> None:
    """Imprime la URL del servicio."""
    g.run("run", "services", "describe", service, "--region", cfg.region, "--format", "value(status.url)")


# CLI


def build_parser() -> argparse.ArgumentParser:
    """Construye el analizador de argumentos con todos los subcomandos."""
    p = argparse.ArgumentParser(prog="deploy/portal.py", description="Despliegue del portal web (Cloud Run).")
    p.add_argument("--project", help="ID del proyecto (o PROJECT_ID / gcloud config)")
    p.add_argument("--region", default=None, help="región (def.: REGION, GCP_REGION o us-east1)")
    p.add_argument("--dry-run", action="store_true", help="imprime los comandos de gcloud sin ejecutarlos")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("secrets", help="sube usuarios y llave de sesión a Secret Manager")
    s.add_argument("--users-file", type=Path, default=Path("users.json"))
    for name, text in (("infra", "cuenta st-portal y permisos mínimos"), ("deploy", "construye y publica el servicio"),
                       ("up", "infra + deploy")):
        c = sub.add_parser(name, help=text)
        c.add_argument("--trigger", choices=TRIGGERS, default="jobs",
                       help="jobs: ejecuta st-send/st-receive/st-verify directamente (def.) | airflow: dispara el DAG")
        if name != "infra":
            c.add_argument("--airflow-uri", help="URL de Airflow (si se omite, se consulta a Composer)")
            c.add_argument("--environment", default=DEFAULT_ENVIRONMENT, help="entorno de Composer (modo airflow)")
            c.add_argument("--tag", help="etiqueta de la imagen (def.: fecha UTC)")
            c.add_argument("--service", default=SERVICE)
            c.add_argument("--private", action="store_true", help="exige identidad de Google para abrir la URL (IAP/IAM)")
    sub.add_parser("url", help="imprime la URL del portal")
    return p


def main(argv: list[str] | None = None) -> int:
    """
    Punto de entrada.

    Returns:
        0 si todo salió bien, 1 si hubo un error controlado, 130 si el usuario interrumpió.
    """
    import os

    args = build_parser().parse_args(argv)
    try:
        project = resolve_project(args.project)
        region = args.region or os.environ.get("REGION") or os.environ.get("GCP_REGION") or "us-east1"
        cfg = Config(project_id=project, region=region)
        g = Gcloud(project, dry_run=args.dry_run)
        if args.command == "secrets":
            cmd_secrets(cfg, g, args.users_file)
        elif args.command == "infra":
            cmd_infra(cfg, g, args.trigger)
        elif args.command in ("deploy", "up"):
            if args.command == "up":
                cmd_infra(cfg, g, args.trigger)
            cmd_deploy(cfg, g, args.trigger, args.airflow_uri, args.tag, args.service, args.environment, not args.private)
        elif args.command == "url":
            cmd_url(cfg, g)
        return 0
    except DeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
