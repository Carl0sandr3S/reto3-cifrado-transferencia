#!/usr/bin/env python3
"""Airflow en Cloud Composer para securetransfer (solo biblioteca estándar; invoca la CLI `gcloud`).

    python deploy/composer.py images                         # explica los alias de imagen (gcloud no lista versiones)
    python deploy/composer.py create [--image-version IMG]   # (def. composer-3-airflow-2) cuenta del orquestador + entorno de Composer (tarda ~25 min)
    python deploy/composer.py wire                           # permisos mínimos + sube el DAG (el entorno debe estar RUNNING)
    python deploy/composer.py up [--image-version IMG]       # create + wire
    python deploy/composer.py trigger --object a.txt [--upload ./a.txt]   # dispara el DAG (opcional: sube el archivo antes)
    python deploy/composer.py status                         # estado del entorno
    python deploy/composer.py delete --yes                   # borra el entorno (Composer cobra mientras exista)

Opciones globales: --project, --region, --environment, --dry-run (imprime los comandos sin ejecutarlos).
Reutiliza Gcloud, Config y los comandos grant-orchestrator / dag-import de deploy/gcp.py.
Los comandos se pasan como listas (sin shell): no hay interpolación de texto en una línea de comandos.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # permite `python deploy/composer.py` desde la raíz

from deploy.gcp import (  # noqa: E402  (después de ajustar sys.path)
    COMPOSER_ENV_RE,
    Config,
    DeployError,
    Gcloud,
    bind_bucket_role,
    cmd_audit_table,
    cmd_dag_import,
    cmd_grant_orchestrator,
    resolve_project,
)

DEFAULT_ENVIRONMENT = "st-airflow"
SA_ORCHESTRATOR = "st-orchestrator"  # solo opera Composer y ejecuta los jobs: sin KMS ni lectura de datos
DAG_ID = "securetransfer_cloud_run"  # debe coincidir con dag_id de dags/securetransfer_dag.py
COMPOSER_APIS = ["composer.googleapis.com"]
ROLE_WORKER = "roles/composer.worker"
ROLE_SERVICE_AGENT = "roles/composer.ServiceAgentV2Ext"  # según la documentación de Composer para cuentas propias
ROLE_RUN_VIEWER = "roles/run.viewer"  # permite leer la operación de Cloud Run (run.operations.get): sin esto el operador no puede esperar al job
ROLE_LIST_BUCKET = "roles/storage.legacyBucketReader"  # lista objetos y NO los lee (el sensor solo necesita listar). El listado no se puede acotar a portal/ con IAM

DEFAULT_ENV_SIZE = "small"  # el tamaño más bajo de Composer 3: suficiente para orquestar 3 jobs
ENV_SIZES = ("small", "medium", "large")
DEFAULT_IMAGE_VERSION = "composer-3-airflow-2"  # Composer 3 + última Airflow 2.x: el DAG usa imports de Airflow 2
IMAGE_VERSION_RE = re.compile(r"^composer-[A-Za-z0-9.\-]+$")
PROJECT_NUMBER_RE = re.compile(r"^[0-9]+$")
OBJECT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/ ]*$")  # nombre de objeto de GCS razonable, sin caracteres de control


class ComposerGcloud(Gcloud):
    """Gcloud que pone --project ANTES del separador `--`.

    `gcloud composer environments run ... -- ARGS` pasa todo lo que va después de `--` a Airflow; si --project
    quedara al final, Airflow lo recibiría como argumento propio y fallaría.
    """

    def _cmd(self, args) -> list[str]:
        """
        Construye el comando de gcloud colocando --project antes de `--` si existe.

        Args:
            args: Argumentos de gcloud (sin el ejecutable).

        Returns:
            Lista de argumentos lista para subprocess.
        """
        parts = [str(a) for a in args]
        if "--" in parts:
            at = parts.index("--")
            return ["gcloud", *parts[:at], "--project", self.project, *parts[at:]]
        return super()._cmd(args)


# Validaciones


def _check_environment(environment: str) -> None:
    """
    Valida el nombre del entorno de Composer.

    Args:
        environment: Nombre del entorno.

    Raises:
        DeployError: Si no cumple el formato (minúsculas, dígitos y guiones; empieza por letra).
    """
    if not COMPOSER_ENV_RE.match(environment):
        raise DeployError("--environment debe usar minúsculas, dígitos y guiones, y empezar por una letra")


def _check_image_version(image_version: str | None) -> None:
    """
    Valida la versión de imagen de Composer (si se indicó).

    Args:
        image_version: Valor de --image-version o None.

    Raises:
        DeployError: Si no empieza por 'composer-' o contiene caracteres no permitidos.
    """
    if image_version is not None and not IMAGE_VERSION_RE.match(image_version):
        raise DeployError("--image-version debe ser como composer-3-airflow-2 o composer-3-airflow-2.10.5-build.N (use el subcomando 'images')")


def _check_object(name: str) -> None:
    """
    Valida el nombre del objeto que se pasará al DAG.

    Args:
        name: Nombre del objeto dentro de bronze/portal/.

    Raises:
        DeployError: Si está vacío, tiene caracteres raros o intenta salir de la carpeta ('..').
    """
    if not OBJECT_RE.match(name) or ".." in name.split("/"):
        raise DeployError(f"Nombre de objeto no válido: {name!r}")


def orchestrator_email(cfg: Config) -> str:
    """
    Correo de la cuenta de servicio del orquestador.

    Args:
        cfg: Configuración del proyecto.

    Returns:
        nombre@proyecto.iam.gserviceaccount.com
    """
    return cfg.sa_email(SA_ORCHESTRATOR)


def project_number(cfg: Config, g: Gcloud, given: str | None) -> str:
    """
    Obtiene el número del proyecto (el agente de servicio de Composer se nombra con él, no con el ID).

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        given: Valor de --project-number, si el usuario lo indicó.

    Returns:
        El número del proyecto ("PROJECT_NUMBER" como marcador en dry-run).

    Raises:
        DeployError: Si el valor no es numérico.
    """
    number = given or g.run("projects", "describe", cfg.project_id, "--format", "value(projectNumber)", capture=True).strip()
    if g.dry_run and not number:
        return "PROJECT_NUMBER"
    if not PROJECT_NUMBER_RE.match(number):
        raise DeployError("No se pudo obtener el número del proyecto; pásalo con --project-number")
    return number


# Comandos


def cmd_images(cfg: Config, g: Gcloud) -> None:
    """
    Muestra las versiones de imagen de Composer disponibles en la región.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
    """
    # gcloud (GA) no tiene un subcomando para listar versiones; `create --image-version` acepta alias que
    # se resuelven a la última versión compatible, así que no hace falta conocer el número exacto.
    print(
        "gcloud no lista versiones de imagen. Use un alias (se resuelve a la última versión disponible):\n"
        "  composer-3-airflow-2      Composer 3 + última Airflow 2.x  (recomendada: el DAG usa imports de Airflow 2)\n"
        "  (No use composer-3-airflow-3: el DAG es de Airflow 2.x y no cargaría.)\n"
        "Pase el alias con:  python deploy/composer.py create --image-version composer-3-airflow-2\n"
        "La versión resuelta se ve después con:  python deploy/composer.py status"
    )


def cmd_create(cfg: Config, g: Gcloud, environment: str, image_version: str | None,
               number: str | None = None, wait: bool = True, environment_size: str = DEFAULT_ENV_SIZE) -> None:
    """
    Crea (idempotente) la cuenta del orquestador y el entorno de Composer.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno.
        image_version: Versión de imagen; si es None se usa DEFAULT_IMAGE_VERSION (Airflow 2.x).
        number: Número del proyecto (se consulta si no se indica).
        wait: Si es False, vuelve sin esperar a que termine la creación.
        environment_size: Tamaño del entorno (small, medium o large). small es el más económico.

    Raises:
        DeployError: Si algún dato es inválido o falla un comando de gcloud.
    """
    _check_environment(environment)
    image_version = image_version or DEFAULT_IMAGE_VERSION
    _check_image_version(image_version)
    sa = orchestrator_email(cfg)
    print(f">> Proyecto {cfg.project_id}  región {cfg.region}  entorno {environment}")
    g.run("services", "enable", *COMPOSER_APIS)

    if not g.ok("iam", "service-accounts", "describe", sa):
        g.run("iam", "service-accounts", "create", SA_ORCHESTRATOR, "--display-name", "securetransfer Airflow orquestador")
    g.run("projects", "add-iam-policy-binding", cfg.project_id, "--member", f"serviceAccount:{sa}",
          "--role", ROLE_WORKER, "--condition=None", retries=3)

    agent = f"serviceAccount:service-{project_number(cfg, g, number)}@cloudcomposer-accounts.iam.gserviceaccount.com"
    g.run("projects", "add-iam-policy-binding", cfg.project_id, "--member", agent,
          "--role", ROLE_SERVICE_AGENT, "--condition=None", retries=3)

    if g.ok("composer", "environments", "describe", environment, "--location", cfg.region):
        print(f">> El entorno {environment} ya existe; no se vuelve a crear")
        return
    args = ["composer", "environments", "create", environment, "--location", cfg.region, "--service-account", sa,
            "--image-version", image_version, "--environment-size", environment_size]
    if not wait:
        args.append("--async")
    g.run(*args)


def environment_state(cfg: Config, g: Gcloud, environment: str) -> str:
    """
    Consulta el estado del entorno (RUNNING, CREATING, ERROR...).

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno.

    Returns:
        El estado en texto ("RUNNING" simulado en dry-run).

    Raises:
        DeployError: Si el entorno no existe o gcloud falla.
    """
    _check_environment(environment)
    out = g.run("composer", "environments", "describe", environment, "--location", cfg.region,
                "--format", "value(state)", capture=True)
    return "RUNNING" if g.dry_run else out.strip()


def cmd_wire(cfg: Config, g: Gcloud, environment: str) -> None:
    """
    Da los permisos mínimos al orquestador y sube el DAG. Requiere el entorno en RUNNING.

    Permisos: ejecutar los 3 jobs (grant-orchestrator), LISTAR el bucket bronze para el sensor,
    LEER las operaciones de Cloud Run (roles/run.viewer) para esperar el resultado de cada job y
    ESCRIBIR en la tabla de auditoría de BigQuery (solo esa tabla; ver cmd_audit_table).
    No recibe permisos sobre la llave KMS ni sobre el contenido de los buckets.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno.

    Raises:
        DeployError: Si el entorno no está RUNNING o falla un comando de gcloud.
    """
    state = environment_state(cfg, g, environment)
    if state != "RUNNING":
        raise DeployError(f"El entorno {environment} está en estado {state or 'desconocido'}; espere a RUNNING (use 'status')")
    sa = orchestrator_email(cfg)
    cmd_grant_orchestrator(cfg, g, sa)
    # Listar no se puede limitar a portal/ (es un permiso de bucket); el sensor igualmente solo pregunta por portal/<objeto>
    # (ver dags/securetransfer_paths.py) y Airflow no recibe permiso para LEER objetos.
    bind_bucket_role(g, cfg.bucket_bronze, f"serviceAccount:{sa}", ROLE_LIST_BUCKET, folder_only=False)
    # El operador de Airflow lanza el job y luego CONSULTA la operación hasta que termina. Esa consulta exige
    # run.operations.get, que roles/run.jobsExecutorWithOverrides no incluye. Las operaciones no pertenecen al job
    # sino a la ubicación, por eso el rol va a nivel de proyecto (solo lectura).
    g.run("projects", "add-iam-policy-binding", cfg.project_id, "--member", f"serviceAccount:{sa}",
          "--role", ROLE_RUN_VIEWER, "--condition=None", retries=3)
    cmd_audit_table(cfg, g, sa)  # crea dataset/tabla de auditoría si faltan y da acceso a la cuenta de Airflow
    cmd_dag_import(cfg, g, environment, cfg.region)


def cmd_trigger(cfg: Config, g: Gcloud, environment: str, obj: str, upload: Path | None = None) -> None:
    """
    Dispara el DAG con parámetros; opcionalmente sube antes el archivo a bronze/portal.

    Es lo que permite procesar otro archivo sin tocar el código: solo cambia el nombre del objeto.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno.
        obj: Nombre del objeto dentro de bronze/portal/ (relativo a esa carpeta).
        upload: Ruta local de un archivo que se sube a bronze/portal con ese nombre (opcional).

    Raises:
        DeployError: Si el nombre es inválido, el archivo no existe o falla un comando de gcloud.
    """
    _check_environment(environment)
    _check_object(obj)
    if upload is not None:
        if not upload.is_file() and not g.dry_run:
            raise DeployError(f"No existe el archivo a subir: {upload}")
        g.run("storage", "cp", str(upload), cfg.flow_uri(cfg.bucket_bronze, obj))
    conf = json.dumps({"project_id": cfg.project_id, "region": cfg.region, "object": obj})
    g.run("composer", "environments", "run", environment, "--location", cfg.region,
          "dags", "trigger", "--", DAG_ID, "--conf", conf)


def cmd_status(cfg: Config, g: Gcloud, environment: str) -> None:
    """
    Imprime el estado del entorno y la URL de la interfaz de Airflow.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno.
    """
    print(f"estado: {environment_state(cfg, g, environment)}")
    g.run("composer", "environments", "describe", environment, "--location", cfg.region,
          "--format", "value(config.airflowUri)")


def cmd_delete(cfg: Config, g: Gcloud, environment: str) -> None:
    """
    Borra el entorno de Composer (deja de cobrar). No borra la cuenta st-orchestrator ni los jobs.

    Args:
        cfg: Configuración del proyecto.
        g: Envoltorio de gcloud.
        environment: Nombre del entorno.
    """
    _check_environment(environment)
    g.run("composer", "environments", "delete", environment, "--location", cfg.region, "--quiet")


# CLI


def build_parser() -> argparse.ArgumentParser:
    """
    Construye el analizador de argumentos con todos los subcomandos.

    Returns:
        El ArgumentParser configurado.
    """
    p = argparse.ArgumentParser(prog="deploy/composer.py", description="Airflow en Cloud Composer para securetransfer.")
    p.add_argument("--project", help="ID del proyecto (o PROJECT_ID / gcloud config)")
    p.add_argument("--region", default=os.environ.get("REGION") or os.environ.get("GCP_REGION") or "us-east1")
    p.add_argument("--environment", default=os.environ.get("COMPOSER_ENV", DEFAULT_ENVIRONMENT))
    p.add_argument("--dry-run", action="store_true", help="imprime los comandos de gcloud sin ejecutarlos")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("images", help="lista las imágenes de Composer disponibles")
    for name, text in (("create", "crea la cuenta del orquestador y el entorno"), ("up", "create + wire")):
        s = sub.add_parser(name, help=text)
        s.add_argument("--image-version", help=f"def. {DEFAULT_IMAGE_VERSION}; el DAG requiere Airflow 2.x (ver 'images')")
        s.add_argument("--project-number", help="número del proyecto (si se omite, se consulta)")
        s.add_argument("--environment-size", choices=ENV_SIZES, default=DEFAULT_ENV_SIZE,
                       help="tamaño del entorno (def. small, el más económico)")
        s.add_argument("--no-wait", action="store_true", help="no esperar a que termine la creación")
    sub.add_parser("wire", help="permisos mínimos + tabla de auditoría en BigQuery + sube el DAG")
    sub.add_parser("audit-table", help="crea la tabla de auditoría en BigQuery (sin dar permisos ni tocar Composer)")
    t = sub.add_parser("trigger", help="dispara el DAG")
    t.add_argument("--object", required=True, help="objeto dentro de bronze/portal/")
    t.add_argument("--upload", type=Path, help="archivo local que se sube a bronze/portal con ese nombre")
    sub.add_parser("status", help="estado del entorno y URL de Airflow")
    d = sub.add_parser("delete", help="borra el entorno")
    d.add_argument("--yes", action="store_true", help="confirma el borrado")
    return p


def main(argv: list[str] | None = None) -> int:
    """
    Punto de entrada: interpreta los argumentos y ejecuta el subcomando elegido.

    Args:
        argv: Lista de argumentos; si es None se usan los de sys.argv.

    Returns:
        0 si todo salió bien, 1 si hubo error, 130 si el usuario interrumpió con Ctrl+C.
    """
    args = build_parser().parse_args(argv)
    try:
        cfg = Config(project_id=resolve_project(args.project), region=args.region)
        g = ComposerGcloud(cfg.project_id, dry_run=args.dry_run)
        env = args.environment
        if args.command == "images":
            cmd_images(cfg, g)
        elif args.command in ("create", "up"):
            cmd_create(cfg, g, env, args.image_version, args.project_number, wait=not args.no_wait,
                       environment_size=args.environment_size)
            if args.command == "up":
                if args.no_wait:
                    raise DeployError("'up' necesita esperar la creación; use 'create --no-wait' y luego 'wire'")
                cmd_wire(cfg, g, env)
        elif args.command == "wire":
            cmd_wire(cfg, g, env)
        elif args.command == "audit-table":
            cmd_audit_table(cfg, g)
        elif args.command == "trigger":
            cmd_trigger(cfg, g, env, args.object, args.upload)
        elif args.command == "status":
            cmd_status(cfg, g, env)
        elif args.command == "delete":
            if not args.yes:
                raise DeployError("Borrar el entorno es irreversible: repita el comando con --yes")
            cmd_delete(cfg, g, env)
        return 0
    except DeployError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())