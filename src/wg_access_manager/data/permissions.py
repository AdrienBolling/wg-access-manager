from wg_access_manager.config import CONFIG
from wg_access_manager.utils import (
    git_track as gt,
)
from wg_access_manager import __version__
import os
from typing import Any
import yaml
import json

PERMISSIONS_FILE_PATH = os.path.join(
    os.getenv("WG_AM_ROOT"), CONFIG["data_dir"], CONFIG["services_file"]
)

SERIALIZER = CONFIG.get("serializer", "json")


def read_permissions_table(serializer: str = SERIALIZER) -> dict[str, dict[str, Any]]:
    # Read the permissions_table as a serialized file and return it as a dictionary
    with open(os.path.join(PERMISSIONS_FILE_PATH), mode="r") as f:
        if serializer == "json":
            return json.load(fp=f)
        elif serializer == "yaml":
            return yaml.safe_load(stream=f)
        else:
            raise ValueError(f"Unsupported serializer: {serializer}")


def save_permissions_table(
    table: dict[str, dict[str, Any]], serializer: str = SERIALIZER
) -> None:
    with open(os.path.join(PERMISSIONS_FILE_PATH), mode="w") as f:
        if serializer == "json":
            json.dump(obj=table, fp=f, indent=4)
        elif serializer == "yaml":
            yaml.safe_dump(data=table, stream=f)
        else:
            raise ValueError(f"Unsupported serializer: {serializer}")


def write_permission(user_name: str, service_name: str, allowed: bool) -> None:
    permissions_table = read_permissions_table()
    permissions_table[user_name][service_name] = allowed

    # Ensure tracking in git
    gt(
        PERMISSIONS_FILE_PATH,
        f"perm: user {user_name} {'allowed' if allowed else 'unallowed'} on service {service_name} - v{__version__}",
    )


def get_user_permissions(user_name: str) -> dict[str, bool]:
    permissions_table = read_permissions_table()
    return permissions_table.get(user_name, {})


def get_all_permissions() -> dict[str, dict[str, bool]]:
    return read_permissions_table()
