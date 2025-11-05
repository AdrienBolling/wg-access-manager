# Initilisation script for WireGuard Access Manager
# Sets up the group, permissions, and necessary directories
# Sets up the default configuration files if they do not exist

from wg_access_manager.defaults import defaults
import os
import grp
import getpass
import subprocess
import logging
import pwd
from pathlib import Path

logger = logging.getLogger(__name__)


def ensure_group_exists() -> None:
    group_name = str(defaults["config"]["package_group_name"])
    try:
        _ = grp.getgrnam(group_name)
        logger.info(f"Group '{group_name}' already exists.")
    except KeyError:
        logger.info(f"Group '{group_name}' does not exist. Creating it.")
        _ = subprocess.run(["groupadd", group_name], check=True)


def real_user():
    """
    Best-effort 'human invoker'.
    If run via sudo, prefer $SUDO_USER. Otherwise fall back to LOGNAME/USER/getpass.
    """
    for var in ("SUDO_USER", "LOGNAME", "USER"):
        v = os.environ.get(var)
        if v:
            return v
    # getpass reads LOGNAME/USER or uses pwd.getpwuid(os.getuid())
    return getpass.getuser()


def ensure_user_in_group():
    user = real_user()
    group = str(defaults["config"]["package_group_name"])
    info = pwd.getpwnam(user)
    try:
        g = grp.getgrnam(group)
        members = set(g.gr_mem)
        primary_gid = info.pw_gid
        if info.pw_name in members or g.gr_gid == primary_gid:
            logger.info(f"[ok] {user} already in {group}")
        else:
            logger.info(f"[+] adding {user} to {group}")
            _ = subprocess.run(["usermod", "-aG", group, user], check=True)
    except KeyError:
        raise RuntimeError(f"group {group} does not exist")


def ensure_dir_group_and_mode(
    path: str | Path, group: str, mode: int = 0o2770, owner: str = "root"
):
    p = Path(path)
    if not p.exists():
        print(f"[+] creating directory {p}")
        p.mkdir(parents=True, exist_ok=True)

    uid = pwd.getpwnam(owner).pw_uid
    gid = grp.getgrnam(group).gr_gid

    # chown if needed
    st = p.stat()
    if st.st_uid != uid or st.st_gid != gid:
        print(f"[+] chown {owner}:{group} {p}")
        os.chown(p, uid, gid)

    # ensure setgid bit + perms (e.g., 2770)
    desired = mode
    if (st.st_mode & 0o47777) != desired:
        print(f"[+] chmod {oct(desired)} {p}")
        os.chmod(p, desired)


def make_dirs() -> None:
    group = str(defaults["config"]["package_group_name"])
    user = real_user()
    # Create the package root directory if it doesn't exist
    ensure_dir_group_and_mode(
        str(defaults["env"]["package_root"]),
        group=group,
        owner=user,
    )

    # Create the data subdirectory if it doesn't exist
    ensure_dir_group_and_mode(
        str(defaults["env"]["package_root"]) + str(defaults["env"]["data_subfolder"]),
        group=group,
        owner=user,
    )

    # Create the templates subdirectory if it doesn't exist
    ensure_dir_group_and_mode(
        str(defaults["env"]["package_root"])
        + str(defaults["env"]["templates_subfolder"]),
        group=group,
        owner=user,
    )
