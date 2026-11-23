"""Portal de archivos conectado al flujo securetransfer.

  comercial  -> sube un archivo -> BRONZE/portal -> [st-send cifra] -> SILVER/portal -> [st-receive descifra] -> GOLD/portal
  jefe       <- descarga el archivo recuperado desde GOLD/portal

El portal NO cifra: escribe en BRONZE (solo crear), pide al flujo que corra y lee de GOLD (solo leer).
Todo lo suyo vive en la carpeta portal/ de cada capa (medallion).
Toda la configuración llega por variables de entorno; no hay secretos en el código.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import re
import secrets
import sys
import time
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import (Flask, abort, flash, redirect, render_template, request,
                   send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .audit import audit
from .store import AlreadyExists, GcsStore, LocalStore, NotFound, StoreError
from .trigger import (DEFAULT_DAG_ID, AirflowTrigger, JobsTrigger, LocalFlowTrigger,
                      NoopTrigger, TriggerError)

RUN_PREFIX = "portal-"  # distingue las cargas de la interfaz de las demos/DAG que también usan portal/
RUN_RE = re.compile(r"^portal-(\d{8}T\d{6}Z)-([a-z0-9_.-]{1,32})-([0-9a-f]{6})$")
USER_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
ROLES = {"comercial", "jefe"}
MAX_NAME = 150
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))  # iguala el tiempo si el usuario no existe

log = logging.getLogger("portal")


def _load_users(env) -> dict:
    """USERS_JSON (secreto en la nube) o, si no existe, el archivo USERS_FILE."""
    if env.get("USERS_JSON"):
        users = json.loads(env["USERS_JSON"])
    else:
        path = Path(env.get("USERS_FILE", "users.json"))
        if not path.exists():
            raise RuntimeError(f"No hay usuarios: cree {path} con portal/manage_users.py")
        users = json.loads(path.read_text())
    for name, rec in users.items():
        if not USER_RE.match(name) or rec.get("role") not in ROLES or not rec.get("hash"):
            raise RuntimeError(f"Usuario inválido en la configuración: {name!r}")
    return users


def _build_store(cfg: dict):
    if cfg["STORE"] == "gcs":
        project = cfg["PROJECT_ID"]
        return GcsStore(cfg.get("BUCKET_BRONZE") or f"{project}-bronze",
                        cfg.get("BUCKET_GOLD") or f"{project}-gold")
    return LocalStore(cfg["FLOW_DIR"])


def _build_trigger(cfg: dict):
    mode = cfg["TRIGGER"]
    project, region = cfg.get("PROJECT_ID", ""), cfg["REGION"]
    if mode == "jobs":
        return JobsTrigger(project, region)
    if mode == "airflow":
        if not cfg.get("AIRFLOW_URI"):
            raise RuntimeError("PORTAL_TRIGGER=airflow requiere AIRFLOW_URI")
        return AirflowTrigger(cfg["AIRFLOW_URI"], project, region, cfg.get("AIRFLOW_DAG_ID", DEFAULT_DAG_ID))
    if mode == "local":
        from securetransfer.keys import build_provider  # solo desarrollo (está en el repositorio)
        return LocalFlowTrigger(cfg["FLOW_DIR"], build_provider("local", None, os.environ.get("SECXFER_LOCAL_KEY")))
    if mode == "none":
        return NoopTrigger()
    raise RuntimeError(f"PORTAL_TRIGGER desconocido: {mode!r} (jobs, airflow, local o none)")


def create_app(config: dict | None = None) -> Flask:
    app = Flask(__name__)
    env = os.environ
    app.config.update(
        SECRET_KEY=env.get("SECRET_KEY") or secrets.token_hex(32),
        STORE=env.get("PORTAL_STORE", "local"),            # gcs | local
        TRIGGER=env.get("PORTAL_TRIGGER", "none"),         # jobs | airflow | local | none
        PROJECT_ID=env.get("PROJECT_ID", ""),
        REGION=env.get("REGION", "us-east1"),
        AIRFLOW_URI=env.get("AIRFLOW_URI", ""),
        AIRFLOW_DAG_ID=env.get("AIRFLOW_DAG_ID", DEFAULT_DAG_ID),
        FLOW_DIR=env.get("FLOW_DIR", "dev-flow"),
        MAX_CONTENT_LENGTH=int(env.get("MAX_UPLOAD_MB", "25")) * 1024 * 1024,  # Cloud Run admite hasta 32 MiB por petición
        ALLOWED_EXTENSIONS={e.strip().lower() for e in env.get(
            "ALLOWED_EXTENSIONS", "pdf,doc,docx,xls,xlsx,csv,txt,png,jpg,jpeg").split(",")},
        SESSION_COOKIE_SECURE=env.get("COOKIE_SECURE", "1") == "1",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=int(env.get("SESSION_MINUTES", "30")) * 60,
    )
    if config:
        app.config.update(config)

    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(message)s")
    users = app.config.get("USERS") or _load_users(env)
    store = app.config.get("STORE_OBJ") or _build_store(app.config)
    trigger = app.config.get("TRIGGER_OBJ") or _build_trigger(app.config)
    app.extensions["portal_trigger"] = trigger  # las pruebas esperan el flujo con wait_all()

    # ---------------------------------------------------------- utilidades
    def current_user():
        return session.get("user")

    def role_required(role):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                if not current_user():
                    return redirect(url_for("login"))
                if session.get("role") != role:
                    audit("forbidden", user=current_user(), path=request.path)
                    abort(403)
                return fn(*a, **kw)
            return wrapper
        return deco

    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")):
                abort(400)

    @app.after_request
    def security_headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    def new_run_id(user: str) -> str:
        return f"{RUN_PREFIX}{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{user}-{secrets.token_hex(3)}"

    # --------------------------------------------------------------- rutas
    @app.get("/")
    def index():
        if not current_user():
            return redirect(url_for("login"))
        return redirect(url_for("upload" if session["role"] == "comercial" else "files"))

    @app.get("/healthz")
    def healthz():
        return "ok"

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            name = request.form.get("usuario", "").strip().lower()
            rec = users.get(name)
            ok = check_password_hash(rec["hash"] if rec else _DUMMY_HASH, request.form.get("clave", ""))
            if rec and ok:
                session.clear()
                session.permanent = True
                session.update(user=name, role=rec["role"])
                audit("login_ok", user=name)
                return redirect(url_for("index"))
            audit("login_fail", user=name[:50])
            flash("Usuario o clave incorrectos.")
        return render_template("login.html")

    @app.post("/logout")
    def logout():
        audit("logout", user=current_user())
        session.clear()
        return redirect(url_for("login"))

    @app.route("/subir", methods=["GET", "POST"])
    @role_required("comercial")
    def upload():
        receipt = None
        if request.method == "POST":
            f = request.files.get("archivo")
            name = secure_filename(f.filename)[:MAX_NAME] if f and f.filename else ""
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            data = f.read() if f else b""
            if not name or not data:
                flash("Selecciona un archivo que no esté vacío.")
            elif ext not in app.config["ALLOWED_EXTENSIONS"]:
                flash("Tipo de archivo no permitido.")
            else:
                run_id = new_run_id(current_user())
                obj = f"{run_id}/{name}"
                sha = hashlib.sha256(data).hexdigest()
                try:
                    store.put_bronze(obj, data)
                except StoreError as exc:
                    audit("upload_failed", user=current_user(), run_id=run_id, error=str(exc)[:200])
                    flash("No se pudo guardar el archivo. Intenta de nuevo.")
                    return render_template("upload.html", receipt=None)
                audit("upload", user=current_user(), run_id=run_id, bytes=len(data), sha256=sha)
                receipt = {"run_id": run_id, "nombre": name, "bytes": len(data), "sha256": sha, "iniciado": True}
                try:
                    trigger.start(run_id, obj)
                except TriggerError as exc:
                    audit("flow_not_started", user=current_user(), run_id=run_id, error=str(exc)[:200])
                    receipt["iniciado"] = False
        return render_template("upload.html", receipt=receipt)

    @app.get("/archivos")
    @role_required("jefe")
    def files():
        try:
            entries = store.list_gold(RUN_PREFIX)
        except StoreError as exc:
            audit("list_failed", user=current_user(), error=str(exc)[:200])
            abort(500, "No se pudo consultar la lista de archivos.")
        items = []
        for e in entries:
            run, _, name = e.name.partition("/")
            m = RUN_RE.match(run)
            if not m or not name or "/" in name:  # solo cargas del portal, un nivel
                continue
            ts = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            items.append({"run": run, "nombre": name, "subido_por": m.group(2), "ts": ts,
                          "fecha": ts.strftime("%Y-%m-%d %H:%M UTC"), "kb": max(1, round(e.size / 1024))})
        items.sort(key=lambda i: i["ts"], reverse=True)
        return render_template("files.html", items=items)

    @app.get("/archivos/<run>/<name>")
    @role_required("jefe")
    def download(run, name):
        if not RUN_RE.match(run) or name != secure_filename(name) or not name:
            abort(404)
        try:
            data = store.get_gold(f"{run}/{name}")
        except NotFound:
            abort(404)
        except StoreError as exc:
            audit("download_failed", user=current_user(), run_id=run, error=str(exc)[:200])
            abort(500, "No se pudo leer el archivo.")
        audit("download", user=current_user(), run_id=run, bytes=len(data),
              sha256=hashlib.sha256(data).hexdigest())
        return send_file(io.BytesIO(data), as_attachment=True, download_name=name)

    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(500)
    def error(e):
        code = getattr(e, "code", 500)
        texts = {403: "No tienes permiso para ver esto.", 404: "No encontrado.",
                 413: "El archivo supera el tamaño máximo permitido.",
                 500: getattr(e, "description", None) or "Error interno."}
        return render_template("error.html", msg=texts.get(code, "Error.")), code

    return app


# Para gunicorn:  gunicorn "portal.app:create_app()"
if __name__ == "__main__":  # solo desarrollo local
    create_app().run(host="127.0.0.1", port=int(os.environ.get("PORT", "8080")))
