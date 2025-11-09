# Default values used
#
# All of these are only used for initial setup.
# The actual values used are defined as ENV variables in /etc/profile.d/wg-access-manager.sh

defaults = {
    "env": {
        "services_root": "/srv/",
        "package_root": "/opt/wg-access-manager/",
    },
    "config": {
        "templates_dir": "templates/",
        "data_dir": "data/",
        "users_file": "users.json",
        "services_file": "services.json",
        "permissions_file": "permissions.json",
        "vpn_definitions_file": "vpn_definitions.json",
        "package_goup_name": "wg-access-manager",
        "ignored_services_folders": [
            "vpn"
        ],  # Exceptional services_root subfolders to ignore
    },
}
