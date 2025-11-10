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
from wg_access_manager.data.service import read_service_table

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


def save_user_table(
    table: dict[str, dict[str, Any]], serializer: str = SERIALIZER
) -> None:
    with open(os.path.join(USER_FILE_PATH), mode="w") as f:
        if serializer == "json":
            json.dump(obj=table, fp=f, indent=4)
        elif serializer == "yaml":
            yaml.safe_dump(data=table, stream=f)
        else:
            raise ValueError(f"Unsupported serializer: {serializer}")


def get_next_free_user_ip() -> str:
    user_network = ipad.IPv4Network(address=CONFIG.wg_user_network)
    user_table = read_user_table()
    # Find any gap in ip addresses of the users
    for ip in user_network.hosts():
        ip_str = str(ip)
        if ip_str not in [user_info["ip"] for user_info in user_table.values()]:
            return ip_str
    raise RuntimeError(
        "No free IP addresses available in the user network. Can't create new user."
    )


def gen_wg_keys() -> tuple[str, str, str]:
    # Generate a new WireGuard key pair and return the public key, private key, and preshared key
    pvt_key = cso(subprocess.run(["wg", "genkey"], capture_output=True, check=True))
    pub_key = cso(
        subprocess.run(["wg", "pubkey", pvt_key], capture_output=True, check=True)
    )
    preshared_key = cso(
        subprocess.run(["wg", "genpsk"], capture_output=True, check=True)
    )
    return (pvt_key, pub_key, preshared_key)


def create_user_record(name: str) -> None:
    # The package is authoritative, thus we handle the creation of the user public and private key, as well as the choice of the IP here.

    # Get the public / private key from the wg utility
    # Get the ip by first checking the current highest user IP in use, or any gap in the IP range, and setting the new user to the next available IP
    ip = get_next_free_user_ip()
    pvt_key, pub_key, preshared_key = gen_wg_keys()
    table = read_user_table()
    # Check if the user already exists
    if name in table.keys():
        raise KeyError(f"User {name} already exists in user table.")
    # Check if the name is already used by a service
    if name in read_service_table().keys():
        raise KeyError(f"Name {name} is already used by a service.")
    table[name] = {
        "ip": ip,
        "pvkey": pvt_key,
        "pbkey": pub_key,
        "pskey": preshared_key,
        "last_handshake": None,
        "groups": None,
    }
    # Save the table back to the user file
    save_user_table(table)
    # Ensure tracking in git
    gt(USER_FILE_PATH, message=f"usr: add record for {name} - v{__version__}")


def get_user_record(name: str) -> dict[str, Any]:
    table = read_user_table()
    if name not in table:
        raise KeyError(f"User {name} not found in user table.")
    return table[name]


def get_all_users() -> list[str]:
    table = read_user_table()
    return list(table.keys())


def delete_user_record(name: str) -> None:
    # Delete a user from the user table
    table = read_user_table()
    table.pop(name, None)
    # Save the user table back
    save_user_table(table)
    # Ensure tracking in git
    gt(USER_FILE_PATH, message=f"usr: delete record for {name} - v{__version__}")
