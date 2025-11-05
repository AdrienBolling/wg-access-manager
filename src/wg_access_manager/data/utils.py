from wg_access_manager.config import CONFIG
from wg_access_manager.utils import (
    clean_subprocess_output as cso,
    git_track as gt,
)
import os

def create_user_record(
    name: str
) -> None:
    # The package is authoritative, thus we handle the creation of the user public and private key, as well as the choice of the IP here.

    # Get the 
