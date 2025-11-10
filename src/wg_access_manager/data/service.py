from wg_access_manager.config import CONFIG
from wg_access_manager.utils import (
    clean_subprocess_output as cso,
    git_track as gt,
)
from wg_access_manager import __version__
import os
from typing import Any
import yaml
import ipaddress as ipad
import subprocess
import json

SERVICES_FILE_PATH = os.path.join(
    os.getenv("WG_AM_ROOT"), CONFIG.data_dir, CONFIG.services_file
)
USER_FILE_PATH = os.path.join(
    os.getenv("WG_AM_ROOT"), CONFIG.data_dir, CONFIG.users_file
)

SERIALIZER = CONFIG.get("serializer", "json")


def read_user_table(serializer: str = SERIALIZER) -> dict[str, dict[str, Any]]:
    # Read the user_table as a yaml file and return it as a dictionary
    with open(os.path.join(USER_FILE_PATH), mode="r") as f:
        if serializer == "json":
            return json.load(fp=f)
        elif serializer == "yaml":
            return yaml.safe_load(stream=f)
        else:
            raise ValueError(f"Unsupported serializer: {serializer}")


def read_service_table(serializer: str = SERIALIZER) -> dict[str, dict[str, Any]]:
    # Read the service_table as a serialized file and return it as a dictionary
    with open(os.path.join(SERVICES_FILE_PATH), mode="r") as f:
        if serializer == "json":
            return json.load(fp=f)
        elif serializer == "yaml":
            return yaml.safe_load(stream=f)
        else:
            raise ValueError(f"Unsupported serializer: {serializer}")


def save_service_table(
    table: dict[str, dict[str, Any]], serializer: str = SERIALIZER
) -> None:
    with open(os.path.join(SERVICES_FILE_PATH), mode="w") as f:
        if serializer == "json":
            json.dump(obj=table, fp=f, indent=4)
        elif serializer == "yaml":
            yaml.safe_dump(data=table, stream=f)
        else:
            raise ValueError(f"Unsupported serializer: {serializer}")


def get_next_free_service_ip() -> str:
    service_network = ipad.IPv4Network(address=CONFIG.wg_service_network)
    service_table = read_service_table()
    # Find any gap in ip addresses of the services
    for ip in service_network.hosts():
        ip_str = str(ip)
        if ip_str not in [
            service_info["ip"] for service_info in service_table.values()
        ]:
            return ip_str
    raise RuntimeError(
        "No free IP addresses available in the service network. Can't create new service."
    )


def gen_wg_keys() -> tuple[str, str, str]:
    # Create a new WireGuard key pair and return the
    # public key, private key, and preshared key
    pvt_key = cso(subprocess.run(["wg", "genkey"], capture_output=True, check=True))
    pub_key = cso(
        subprocess.run(["wg", "pubkey", pvt_key], capture_output=True, check=True)
    )
    preshared_key = cso(
        subprocess.run(["wg", "genpsk"], capture_output=True, check=True)
    )

    return pub_key, pvt_key, preshared_key


def create_service_record(
    name: str, ports: dict[str, Any] | None = None, directory: str | None = None
) -> None:
    ip = get_next_free_service_ip()
    pvkey, pbkey, pskey = gen_wg_keys()
    table = read_service_table()
    # Check if the service already exists
    if name in table.keys():
        raise KeyError(f"Service {name} already exists in the service table.")
    if name in read_user_table().keys():
        raise KeyError(f"Name {name} already exists in the user table.")
    table[name] = {
        "ip": ip,
        "pvkey": pvkey,
        "pbkey": pbkey,
        "pskey": pskey,
        "directory": directory if directory else name,
        "ports": ports if ports else {},
        "last_handshake": "None",
        "groups": ["admin"],
    }

    # Save the service table
    save_service_table(table)
    # Ensure tracking in git
    gt(
        file_path=SERVICES_FILE_PATH,
        commit_message=f"srv: add record for {name} - v{__version__}",
    )


def get_service_record(name: str) -> dict[str, Any] | None:
    table = read_service_table()
    if name not in table:
        raise KeyError(f"Service {name} not found in the service table.")
    return table.get(name, None)


def get_all_service() -> dict[str, dict[str, Any]]:
    all_services = read_service_table()
    return list(all_services.keys())


def delete_service_record(name: str) -> None:
    # Delete a service record from the service table
    table = read_service_table()
    table.pop(name, None)
    # Save the service table
    save_service_table(table)
    # Ensure tracking in git
    gt(
        file_path=SERVICES_FILE_PATH,
        commit_message=f"srv: delete record for {name} - v{__version__}",
    )
