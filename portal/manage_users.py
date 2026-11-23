"""Crea o actualiza usuarios del portal (la clave se guarda con hash; nunca en texto plano).

Uso:
    python -m portal.manage_users add maria comercial
    python -m portal.manage_users add carlos jefe
    python -m portal.manage_users list

El resultado es users.json (ignorado por git, permisos 0600). `python deploy/portal.py secrets` lo sube a
Secret Manager; el contenedor lo recibe como variable USERS_JSON.
"""

import getpass
import json
import os
import re
import stat
import sys
from pathlib import Path

from werkzeug.security import generate_password_hash

ROLES = {"comercial", "jefe"}
USER_RE = re.compile(r"^[a-z0-9_.-]{1,32}$")
PATH = Path(os.environ.get("USERS_FILE", "users.json"))


def load() -> dict:
    return json.loads(PATH.read_text()) if PATH.exists() else {}


def main(argv: list[str]) -> int:
    if argv == ["list"]:
        for name, rec in sorted(load().items()):
            print(f"{name}\t{rec['role']}")
        return 0
    if len(argv) != 3 or argv[0] != "add" or argv[2] not in ROLES:
        print(__doc__)
        return 2
    name, role = argv[1].strip().lower(), argv[2]
    if not USER_RE.match(name):
        print("El usuario solo puede tener letras minúsculas, números, '.', '_' y '-' (máx. 32).")
        return 1
    pwd = getpass.getpass("Clave (mín. 12 caracteres): ")
    if len(pwd) < 12 or pwd != getpass.getpass("Repite la clave: "):
        print("Clave muy corta o no coincide.")
        return 1
    users = load()
    users[name] = {"hash": generate_password_hash(pwd), "role": role}
    PATH.write_text(json.dumps(users, indent=2))
    PATH.chmod(stat.S_IRUSR | stat.S_IWUSR)
    print(f"Usuario '{name}' ({role}) guardado en {PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
