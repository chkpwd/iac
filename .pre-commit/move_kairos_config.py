"""Move kairos files to another directory"""

import os
import shutil

HOME_DIR = os.getenv("HOME")


def move_kairos_config():
    """Move kairos cloud-config.yaml.j2 to kairos/multi-node-k3s"""
    src = "../roles/kairos/templates/cloud-config.yaml.j2"
    dest = f"{HOME_DIR}/kairos/multi-node-k3s/cloud-config.yaml.j2"
    shutil.move(src, dest)
