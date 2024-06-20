#!/usr/bin/env python3

"""Move kairos files to another directory"""

import shutil
from pathlib import Path

if __name__ == "__main__":
    src_file = Path.home().joinpath(
        "code", "iac", "ansible", "roles", "kairos", "templates", "cloud-config.yaml.j2"
    )
    dest_file = Path.home().joinpath(
        "code", "kairos", "multi-node-k3s", "cloud-config.example.yaml"
    )

    shutil.copy(src_file, dest_file)
