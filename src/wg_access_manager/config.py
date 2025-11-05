# Reads the package configuration and loads it into memory.

import os
from wg_access_manager.defaults import defaults
import yaml

PACKAGE_ROOT = os.getenv(
    "PACKAGE_ROOT", str(defaults["env"]["package_root"])
)  # Ensure the ENV is read

CONFIG_FILE_NAME = "config.yaml"

config = {}
with open(os.path.join(PACKAGE_ROOT, CONFIG_FILE_NAME), "r") as f:
    config = yaml.safe_load(f)

CONFIG = config
