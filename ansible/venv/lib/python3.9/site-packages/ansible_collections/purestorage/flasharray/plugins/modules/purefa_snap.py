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
module: purefa_snap
version_added: '1.0.0'
short_description: Manage volume snapshots on Pure Storage FlashArrays
description:
- Create or delete volumes and volume snapshots on Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the source volume.
    type: str
    required: true
  suffix:
    description:
    - Suffix of snapshot name.
    - Not used during creation if I(offload) is provided.
    type: str
  target:
    description:
    - Name of target volume if creating from snapshot.
    - Name of new snapshot suffix if renaming a snapshot
    type: str
  overwrite:
    description:
    - Define whether to overwrite existing volume when creating from snapshot.
    type: bool
    default: false
  offload:
    description:
    - Only valid for Purity//FA 6.1 or higher
    - Name of offload target for the snapshot.
    - Target can be either another FlashArray or an Offload Target
    - This is only applicable for creation, deletion and eradication of snapshots
    - I(state) of I(copy) is not supported.
    - I(suffix) is not supported for offload snapshots.
    type: str
  state:
    description:
    - Define whether the volume snapshot should exist or not.
    choices: [ absent, copy, present, rename ]
    type: str
    default: present
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash.
    type: bool
    default: false
  ignore_repl:
    description:
    - Only valid for Purity//FA 6.1 or higher
    - If set to true, allow destruction/eradication of snapshots in use by replication.
    - If set to false, allow destruction/eradication of snapshots not in use by replication
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create snapshot foo.ansible
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: ansible
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create R/W clone foo_clone from snapshot foo.snap
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: snap
    target: foo_clone
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Create R/W clone foo_clone from remote mnapshot arrayB:foo.snap
  purestorage.flasharray.purefa_snap:
    name: arrayB:foo
    suffix: snap
    target: foo_clone
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Overwrite existing volume foo_clone with snapshot foo.snap
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: snap
    target: foo_clone
    overwrite: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Delete and eradicate snapshot named foo.snap
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: snap
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename snapshot foo.fred to foo.dave
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: fred
    target: dave
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: rename

- name: Create a remote volume snapshot on offload device arrayB
  purestorage.flasharray.purefa_snap:
    name: foo
    offload: arrayB
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate a volume snapshot foo.1 on offload device arrayB
  purestorage.flasharray.purefa_snap:
    name: foo
    suffix: 1
    offload: arrayB
    eradicate: true
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PUREERROR = True
try:
    from purestorage import PureHTTPError
except ImportError:
    HAS_PUREERROR = False

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    get_system,
    purefa_argument_spec,
)
from datetime import datetime

GET_SEND_API = "2.4"


def _check_offload(module, array):
    try:
        offload = list(array.get_offloads(names=[module.params["offload"]]).items)[0]
        if offload.status == "connected":
            return True
        return False
    except Exception:
        return False


def _check_target(module, array):
    try:
        target = list(
            array.get_array_connections(names=[module.params["offload"]]).items
        )[0]
        if target.status == "connected":
            return True
        return False
    except Exception:
        return False


def _check_offload_snapshot(module, array):
    """Return Remote Snapshot (active or deleted) or None"""
    source_array = list(array.get_arrays().items)[0].name
    snapname = (
        source_array + ":" + module.params["name"] + "." + module.params["suffix"]
    )
    if _check_offload(module, array):
        res = array.get_remote_volume_snapshots(
            on=module.params["offload"], names=[snapname], destroyed=False
        )
    else:
        res = array.get_volume_snapshots(names=[snapname], destroyed=False)
    if res.status_code != 200:
        return None
    return list(res.items)[0]


def get_volume(module, array):
    """Return Volume or None"""
    try:
        return array.get_volume(module.params["name"])
    except Exception:
        return None


def get_target(module, array):
    """Return Volume or None"""
    try:
        return array.get_volume(module.params["target"])
    except Exception:
        return None


def get_deleted_snapshot(module, array, arrayv6):
    """Return Deleted Snapshot"""
    snapname = module.params["name"] + "." + module.params["suffix"]
    if module.params["offload"]:
        source_array = list(arrayv6.get_arrays().items)[0].name
        snapname = module.params["name"] + "." + module.params["suffix"]
        full_snapname = source_array + ":" + snapname
        if _check_offload(module, arrayv6):
            res = arrayv6.get_remote_volume_snapshots(
                on=module.params["offload"], names=[full_snapname], destroyed=True
            )
        else:
            res = arrayv6.get_volume_snapshots(names=[snapname], destroyed=True)
        if res.status_code == 200:
            return list(res.items)[0].destroyed
        else:
            return False
    else:
        try:
            return bool(
                array.get_volume(snapname, snap=True, pending=True)[0]["time_remaining"]
                != ""
            )
        except Exception:
            return False


def get_snapshot(module, array):
    """Return Snapshot or None"""
    try:
        snapname = module.params["name"] + "." + module.params["suffix"]
        for snaps in array.get_volume(module.params["name"], snap=True, pending=False):
            if snaps["name"] == snapname:
                return True
    except Exception:
        return False


def create_snapshot(module, array, arrayv6):
    """Create Snapshot"""
    changed = False
    if module.params["offload"]:
        module.params["suffix"] = None
        changed = True
        if not module.check_mode:
            res = arrayv6.post_remote_volume_snapshots(
                source_names=[module.params["name"]], on=module.params["offload"]
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to create remote snapshot for volume {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
            else:
                remote_snap = list(res.items)[0].name
                module.params["suffix"] = remote_snap.split(".")[1]
    else:
        changed = True
        if not module.check_mode:
            try:
                array.create_snapshot(
                    module.params["name"], suffix=module.params["suffix"]
                )
            except Exception:
                module.fail_json(
                    msg="Failed to create snapshot for volume {0}".format(
                        module.params["name"]
                    )
                )
    module.exit_json(changed=changed, suffix=module.params["suffix"])


def create_from_snapshot(module, array):
    """Create Volume from Snapshot"""
    source = module.params["name"] + "." + module.params["suffix"]
    tgt = get_target(module, array)
    if tgt is None:
        changed = True
        if not module.check_mode:
            array.copy_volume(source, module.params["target"])
    elif tgt is not None and module.params["overwrite"]:
        changed = True
        if not module.check_mode:
            array.copy_volume(
                source, module.params["target"], overwrite=module.params["overwrite"]
            )
    elif tgt is not None and not module.params["overwrite"]:
        changed = False
    module.exit_json(changed=changed)


def recover_snapshot(module, array, arrayv6):
    """Recover Snapshot"""
    changed = False
    snapname = module.params["name"] + "." + module.params["suffix"]
    if module.params["offload"] and _check_offload(module, arrayv6):
        source_array = list(array.get_arrays().items)[0].name
        snapname = source_array + module.params["name"] + "." + module.params["suffix"]
        changed = True
        if not module.check_mode:
            res = arrayv6.patch_remote_volume_snapshots(
                names=[snapname],
                on=module.params["offload"],
                remote_volume_snapshot=flasharray.DestroyedPatchPost(destroyed=False),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to recover remote snapshot {0}".format(snapname)
                )
    else:
        changed = True
        if not module.check_mode:
            try:
                array.recover_volume(snapname)
            except Exception:
                module.fail_json(msg="Recovery of snapshot {0} failed".format(snapname))
    module.exit_json(changed=changed)


def update_snapshot(module, array):
    """Update Snapshot - basically just rename..."""
    changed = True
    if not module.check_mode:
        current_name = module.params["name"] + "." + module.params["suffix"]
        new_name = module.params["name"] + "." + module.params["target"]
        res = array.patch_volume_snapshots(
            names=[current_name],
            volume_snapshot=flasharray.VolumeSnapshotPatch(name=new_name),
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to rename {0} to {1}. Error: {2}".format(
                    current_name, new_name, res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def delete_snapshot(module, array, arrayv6):
    """Delete Snapshot"""
    changed = False
    snapname = module.params["name"] + "." + module.params["suffix"]
    if module.params["offload"] and _check_offload(module, arrayv6):
        source_array = list(arrayv6.get_arrays().items)[0].name
        full_snapname = source_array + ":" + snapname
        changed = True
        if not module.check_mode:
            res = arrayv6.patch_remote_volume_snapshots(
                names=[full_snapname],
                on=module.params["offload"],
                volume_snapshot=flasharray.VolumeSnapshotPatch(destroyed=True),
                replication_snapshot=module.params["ignore_repl"],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            if module.params["eradicate"]:
                res = arrayv6.delete_remote_volume_snapshots(
                    names=[full_snapname],
                    on=module.params["offload"],
                    replication_snapshot=module.params["ignore_repl"],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
    elif module.params["offload"] and _check_target(module, arrayv6):
        changed = True
        if not module.check_mode:
            res = arrayv6.patch_volume_snapshots(
                names=[snapname],
                volume_snapshot=flasharray.DestroyedPatchPost(destroyed=True),
                replication_snapshot=module.params["ignore_repl"],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to delete remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
            if module.params["eradicate"]:
                res = arrayv6.delete_volume_snapshots(
                    names=[snapname], replication_snapshot=module.params["ignore_repl"]
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
    else:
        changed = True
        if not module.check_mode:
            api_version = array._list_available_rest_versions()
            if GET_SEND_API in api_version:
                module.warn("here")
                res = arrayv6.patch_volume_snapshots(
                    names=[snapname],
                    volume_snapshot=flasharray.DestroyedPatchPost(destroyed=True),
                    replication_snapshot=module.params["ignore_repl"],
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to delete remote snapshot {0}. Error: {1}".format(
                            snapname, res.errors[0].message
                        )
                    )
                if module.params["eradicate"]:
                    res = arrayv6.delete_volume_snapshots(
                        names=[snapname],
                        replication_snapshot=module.params["ignore_repl"],
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                                snapname, res.errors[0].message
                            )
                        )
            else:
                try:
                    array.destroy_volume(snapname)
                    if module.params["eradicate"]:
                        try:
                            array.eradicate_volume(snapname)
                        except PureHTTPError as err:
                            module.fail_json(
                                msg="Error eradicating snapshot. Error: {0}".format(
                                    err.text
                                )
                            )
                except PureHTTPError as err:
                    module.fail_json(
                        msg="Error deleting snapshot. Error: {0}".format(err.text)
                    )
    module.exit_json(changed=changed)


def eradicate_snapshot(module, array, arrayv6):
    """Eradicate snapshot"""
    changed = True
    snapname = module.params["name"] + "." + module.params["suffix"]
    if not module.check_mode:
        if module.params["offload"] and _check_offload(module, arrayv6):
            source_array = list(arrayv6.get_arrays().items)[0].name
            full_snapname = source_array + ":" + snapname
            res = arrayv6.delete_remote_volume_snapshots(
                names=[full_snapname],
                on=module.params["offload"],
                replication_snapshot=module.params["ignore_repl"],
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
        elif module.params["offload"] and _check_target(module, arrayv6):
            res = arrayv6.delete_volume_snapshots(
                names=[snapname], replication_snapshot=module.params["ignore_repl"]
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to eradicate remote snapshot {0}. Error: {1}".format(
                        snapname, res.errors[0].message
                    )
                )
        else:
            try:
                array.eradicate_volume(snapname)
            except Exception:
                changed = False
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            suffix=dict(type="str"),
            target=dict(type="str"),
            offload=dict(type="str"),
            ignore_repl=dict(type="bool", default=False),
            overwrite=dict(type="bool", default=False),
            eradicate=dict(type="bool", default=False),
            state=dict(
                type="str",
                default="present",
                choices=["absent", "copy", "present", "rename"],
            ),
        )
    )

    required_if = [("state", "copy", ["target", "suffix"])]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )
    if not HAS_PUREERROR:
        module.fail_json(msg="purestorage sdk is required for this module")
    pattern1 = re.compile(
        "^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,63}[a-zA-Z0-9])?$"
    )
    pattern2 = re.compile("^([1-9])([0-9]{0,63}[0-9])?$")

    state = module.params["state"]
    if module.params["suffix"] is None:
        suffix = "snap-" + str(
            (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
        )
        module.params["suffix"] = suffix.replace(".", "")
    else:
        if not module.params["offload"]:
            if not (
                pattern1.match(module.params["suffix"])
                or pattern2.match(module.params["suffix"])
            ) and state not in [
                "absent",
                "rename",
            ]:
                module.fail_json(
                    msg="Suffix name {0} does not conform to suffix name rules".format(
                        module.params["suffix"]
                    )
                )
    if state == "rename" and module.params["target"] is not None:
        if not pattern1.match(module.params["target"]):
            module.fail_json(
                msg="Suffix target {0} does not conform to suffix name rules".format(
                    module.params["target"]
                )
            )

    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if GET_SEND_API not in api_version:
        arrayv6 = None
        if module.params["offload"]:
            module.fail_json(
                msg="Purity 6.1, or higher, is required to support single volume offload snapshots"
            )
        if state == "rename":
            module.fail_json(
                msg="Purity 6.1, or higher, is required to support snapshot rename"
            )
    else:
        if not HAS_PURESTORAGE:
            module.fail_json(msg="py-pure-client sdk is required for this module")
        arrayv6 = get_array(module)
        if module.params["offload"]:
            if not _check_offload(module, arrayv6) and not _check_target(
                module, arrayv6
            ):
                module.fail_json(
                    msg="Selected offload {0} not connected.".format(
                        module.params["offload"]
                    )
                )
    if (
        state == "copy"
        and module.params["offload"]
        and not _check_target(module, arrayv6)
    ):
        module.fail_json(
            msg="Snapshot copy is not supported when an offload target is defined"
        )
    destroyed = False
    array_snap = False
    offload_snap = False
    volume = get_volume(module, array)
    if module.params["offload"] and not _check_target(module, arrayv6):
        offload_snap = _check_offload_snapshot(module, arrayv6)
        if offload_snap is None:
            offload_snap = False
        else:
            offload_snap = not offload_snap.destroyed
    else:
        array_snap = get_snapshot(module, array)
    snap = array_snap or offload_snap

    if not snap:
        destroyed = get_deleted_snapshot(module, array, arrayv6)
    if state == "present" and volume and not destroyed:
        create_snapshot(module, array, arrayv6)
    elif state == "present" and destroyed:
        recover_snapshot(module, array, arrayv6)
    elif state == "rename" and volume and snap:
        update_snapshot(module, arrayv6)
    elif state == "copy" and snap:
        create_from_snapshot(module, array)
    elif state == "absent" and snap and not destroyed:
        delete_snapshot(module, array, arrayv6)
    elif state == "absent" and destroyed and module.params["eradicate"]:
        eradicate_snapshot(module, array, arrayv6)
    elif state == "absent" and not snap:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
