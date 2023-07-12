#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_snap
version_added: '1.0.0'
short_description: Manage filesystem snapshots on Pure Storage FlashBlades
description:
- Create or delete volumes and filesystem snapshots on Pure Storage FlashBlades.
- Restoring a filesystem from a snapshot is only supported using
  the latest snapshot.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the source filesystem.
    required: true
    type: str
  suffix:
    description:
    - Suffix of snapshot name.
    type: str
  state:
    description:
    - Define whether the filesystem snapshot should exist or not.
    choices: [ absent, present, restore ]
    default: present
    type: str
  targets:
    description:
    - Name of target to replicate snapshot to.
    - This is only applicable when I(now) is B(true)
    type: list
    elements: str
    version_added: "1.7.0"
  now:
    description:
    - Whether to initiate a snapshot replication immeadiately
    type: bool
    default: false
    version_added: "1.7.0"
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash.
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: Create snapshot foo.ansible
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: ansible
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create immeadiate snapshot foo.ansible to connected FB bar
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: ansible
    now: true
    targets:
    - bar
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete snapshot named foo.snap
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: snap
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Recover deleted snapshot foo.ansible
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: ansible
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Restore filesystem foo (uses latest snapshot)
  purestorage.flashblade.purefb_snap:
    name: foo
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: restore

- name: Eradicate snapshot named foo.snap
  purestorage.flashblade.purefb_snap:
    name: foo
    suffix: snap
    eradicate: true
    fb_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)

from datetime import datetime

HAS_PURITY_FB = True
try:
    from purity_fb import FileSystemSnapshot, SnapshotSuffix, FileSystem, Reference
except ImportError:
    HAS_PURITY_FB = False

SNAP_NOW_API = 1.10


def get_fs(module, blade):
    """Return Filesystem or None"""
    filesystem = []
    filesystem.append(module.params["name"])
    try:
        res = blade.file_systems.list_file_systems(names=filesystem)
        return res.items[0]
    except Exception:
        return None


def get_latest_fssnapshot(module, blade):
    """Get the name of the latest snpshot or None"""
    try:
        filt = "source='" + module.params["name"] + "'"
        all_snaps = blade.file_system_snapshots.list_file_system_snapshots(filter=filt)
        if not all_snaps.items[0].destroyed:
            return all_snaps.items[0].name
        else:
            module.fail_json(
                msg="Latest snapshot {0} is destroyed."
                " Eradicate or recover this first.".format(all_snaps.items[0].name)
            )
    except Exception:
        return None


def get_fssnapshot(module, blade):
    """Return Snapshot or None"""
    try:
        filt = (
            "source='"
            + module.params["name"]
            + "' and suffix='"
            + module.params["suffix"]
            + "'"
        )
        res = blade.file_system_snapshots.list_file_system_snapshots(filter=filt)
        return res.items[0]
    except Exception:
        return None


def create_snapshot(module, blade):
    """Create Snapshot"""
    changed = False
    source = []
    source.append(module.params["name"])
    try:
        if module.params["now"]:
            blade_exists = []
            connected_blades = blade.array_connections.list_array_connections()
            for target in range(0, len(module.params["targets"])):
                blade_exists.append(False)
                for blade in range(0, len(connected_blades)):
                    if (
                        target[target] == connected_blades.items[blade].name
                        and connected_blades.items[blade].status == "connected"
                    ):
                        blade_exists[target] = True
            if not blade_exists:
                module.fail_json(
                    msg="Not all selected targets are correctly connected blades"
                )
            changed = True
            if not module.check_mode:
                blade.file_system_snapshots.create_file_system_snapshots(
                    sources=source,
                    send=True,
                    targets=module.params["targets"],
                    suffix=SnapshotSuffix(module.params["suffix"]),
                )
        else:
            changed = True
            if not module.check_mode:
                blade.file_system_snapshots.create_file_system_snapshots(
                    sources=source, suffix=SnapshotSuffix(module.params["suffix"])
                )
    except Exception:
        changed = False
    module.exit_json(changed=changed)


def restore_snapshot(module, blade):
    """Restore a filesystem back from the latest snapshot"""
    changed = True
    snapname = get_latest_fssnapshot(module, blade)
    if snapname is not None:
        if not module.check_mode:
            fs_attr = FileSystem(
                name=module.params["name"], source=Reference(name=snapname)
            )
            try:
                blade.file_systems.create_file_systems(
                    overwrite=True,
                    discard_non_snapshotted_data=True,
                    file_system=fs_attr,
                )
            except Exception:
                changed = False
    else:
        module.fail_json(
            msg="Filesystem {0} has no snapshots to restore from.".format(
                module.params["name"]
            )
        )
    module.exit_json(changed=changed)


def recover_snapshot(module, blade):
    """Recover deleted Snapshot"""
    changed = True
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        new_attr = FileSystemSnapshot(destroyed=False)
        try:
            blade.file_system_snapshots.update_file_system_snapshots(
                name=snapname, attributes=new_attr
            )
        except Exception:
            changed = False
    module.exit_json(changed=changed)


def update_snapshot(module, blade):
    """Update Snapshot"""
    changed = False
    module.exit_json(changed=changed)


def delete_snapshot(module, blade):
    """Delete Snapshot"""
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        new_attr = FileSystemSnapshot(destroyed=True)
        try:
            blade.file_system_snapshots.update_file_system_snapshots(
                name=snapname, attributes=new_attr
            )
            changed = True
            if module.params["eradicate"]:
                try:
                    blade.file_system_snapshots.delete_file_system_snapshots(
                        name=snapname
                    )
                    changed = True
                except Exception:
                    changed = False
        except Exception:
            changed = False
    module.exit_json(changed=changed)


def eradicate_snapshot(module, blade):
    """Eradicate Snapshot"""
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        try:
            blade.file_system_snapshots.delete_file_system_snapshots(name=snapname)
            changed = True
        except Exception:
            changed = False
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            suffix=dict(type="str"),
            now=dict(type="bool", default=False),
            targets=dict(type="list", elements="str"),
            eradicate=dict(default="false", type="bool"),
            state=dict(default="present", choices=["present", "absent", "restore"]),
        )
    )

    required_if = [["now", True, ["targets"]]]
    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    if module.params["suffix"] is None:
        suffix = "snap-" + str(
            (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
        )
        module.params["suffix"] = suffix.replace(".", "")

    state = module.params["state"]
    blade = get_blade(module)
    versions = blade.api_version.list_versions().versions

    if SNAP_NOW_API not in versions and module.params["now"]:
        module.fail_json(
            msg="Minimum FlashBlade REST version for immeadiate remote snapshots: {0}".format(
                SNAP_NOW_API
            )
        )
    filesystem = get_fs(module, blade)
    snap = get_fssnapshot(module, blade)

    if state == "present" and filesystem and not filesystem.destroyed and not snap:
        create_snapshot(module, blade)
    elif (
        state == "present"
        and filesystem
        and not filesystem.destroyed
        and snap
        and not snap.destroyed
    ):
        update_snapshot(module, blade)
    elif (
        state == "present"
        and filesystem
        and not filesystem.destroyed
        and snap
        and snap.destroyed
    ):
        recover_snapshot(module, blade)
    elif state == "present" and filesystem and filesystem.destroyed:
        update_snapshot(module, blade)
    elif state == "present" and not filesystem:
        update_snapshot(module, blade)
    elif state == "restore" and filesystem:
        restore_snapshot(module, blade)
    elif state == "absent" and snap and not snap.destroyed:
        delete_snapshot(module, blade)
    elif state == "absent" and snap and snap.destroyed:
        eradicate_snapshot(module, blade)
    elif state == "absent" and not snap:
        module.exit_json(changed=False)
    else:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
