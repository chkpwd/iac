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
module: purefa_pgsnap
version_added: '1.0.0'
short_description: Manage protection group snapshots on Pure Storage FlashArrays
description:
- Create or delete protection group snapshots on Pure Storage FlashArray.
- Recovery of replicated snapshots on the replica target array is enabled.
- Support for ActiveCluster and Volume Group protection groups is supported.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the source protection group.
    type: str
    required: true
  suffix:
    description:
    - Suffix of snapshot name.
    - Special case. If I(latest) the module will select the latest snapshot created in the group
    type: str
  state:
    description:
    - Define whether the protection group snapshot should exist or not.
      Copy (added in 2.7) will create a full read/write clone of the
      snapshot.
    type: str
    choices: [ absent, present, copy ]
    default: present
  eradicate:
    description:
    - Define whether to eradicate the snapshot on delete or leave in trash.
    type: bool
    default: false
  restore:
    description:
    - Restore a specific volume from a protection group snapshot.
    - The protection group name is not required. Only provide the name of the
      volume to be restored.
    type: str
  overwrite:
    description:
    - Define whether to overwrite the target volume if it already exists.
    type: bool
    default: false
  target:
    description:
    - Volume to restore a specified volume to.
    - If not supplied this will default to the volume defined in I(restore)
    type: str
  offload:
    description:
    - Name of offload target on which the snapshot exists.
    - This is only applicable for deletion and erasure of snapshots
    type: str
  now:
    description:
    - Whether to initiate a snapshot of the protection group immeadiately
    type: bool
    default: false
  apply_retention:
    description:
    - Apply retention schedule settings to the snapshot
    type: bool
    default: false
  remote:
    description:
    - Force immeadiate snapshot to remote targets
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create protection group snapshot foo.ansible
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: ansible
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete and eradicate protection group snapshot named foo.snap
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: snap
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Restore volume data from local protection group snapshot named foo.snap to volume data2
  purestorage.flasharray.purefa_pgsnap:
    name: foo
    suffix: snap
    restore: data
    target: data2
    overwrite: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Restore remote protection group snapshot arrayA:pgname.snap.data to local copy
  purestorage.flasharray.purefa_pgsnap:
    name: arrayA:pgname
    suffix: snap
    restore: data
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Restore AC pod  protection group snapshot pod1::pgname.snap.data to pdo1::data2
  purestorage.flasharray.purefa_pgsnap:
    name: pod1::pgname
    suffix: snap
    restore: data
    target: pod1::data2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: copy

- name: Create snapshot of existing pgroup foo with suffix and force immeadiate copy to remote targets
  purestorage.flasharray.purefa_pgsnap:
    name: pgname
    suffix: force
    now: true
    apply_retention: true
    remote: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete and eradicate snapshot named foo.snap on offload target bar from arrayA
  purestorage.flasharray.purefa_pgsnap:
    name: "arrayA:foo"
    suffix: snap
    offload: bar
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent
"""

RETURN = r"""
"""

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)

from datetime import datetime

OFFLOAD_API = "1.16"
POD_SNAPSHOT = "2.4"


def _check_offload(module, array):
    try:
        offload = array.get_offload(module.params["offload"])
        if offload["status"] == "connected":
            return True
        return False
    except Exception:
        return None


def get_pgroup(module, array):
    """Return Protection Group or None"""
    try:
        return array.get_pgroup(module.params["name"])
    except Exception:
        return None


def get_pgroupvolume(module, array):
    """Return Protection Group Volume or None"""
    try:
        pgroup = array.get_pgroup(module.params["name"])
        if "::" in module.params["name"]:
            restore_volume = (
                module.params["name"].split("::")[0] + "::" + module.params["restore"]
            )
        else:
            restore_volume = module.params["restore"]
        for volume in pgroup["volumes"]:
            if volume == restore_volume:
                return volume
    except Exception:
        return None


def get_rpgsnapshot(module, array):
    """Return iReplicated Snapshot or None"""
    try:
        snapname = (
            module.params["name"]
            + "."
            + module.params["suffix"]
            + "."
            + module.params["restore"]
        )
        for snap in array.list_volumes(snap=True):
            if snap["name"] == snapname:
                return snapname
    except Exception:
        return None


def get_offload_snapshot(module, array):
    """Return Snapshot (active or deleted) or None"""
    try:
        snapname = module.params["name"] + "." + module.params["suffix"]
        for snap in array.get_pgroup(
            module.params["name"], snap=True, on=module.params["offload"]
        ):
            if snap["name"] == snapname:
                return snapname
    except Exception:
        return None


def get_pgsnapshot(module, array):
    """Return Snapshot (active or deleted) or None"""
    try:
        snapname = module.params["name"] + "." + module.params["suffix"]
        for snap in array.get_pgroup(module.params["name"], pending=True, snap=True):
            if snap["name"] == snapname:
                return snapname
    except Exception:
        return None


def create_pgsnapshot(module, array):
    """Create Protection Group Snapshot"""
    changed = True
    if not module.check_mode:
        try:
            if (
                module.params["now"]
                and array.get_pgroup(module.params["name"])["targets"] is not None
            ):
                array.create_pgroup_snapshot(
                    source=module.params["name"],
                    suffix=module.params["suffix"],
                    snap=True,
                    apply_retention=module.params["apply_retention"],
                    replicate_now=module.params["remote"],
                )
            else:
                array.create_pgroup_snapshot(
                    source=module.params["name"],
                    suffix=module.params["suffix"],
                    snap=True,
                    apply_retention=module.params["apply_retention"],
                )
        except Exception:
            module.fail_json(
                msg="Snapshot of pgroup {0} failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def restore_pgsnapvolume(module, array):
    """Restore a Protection Group Snapshot Volume"""
    api_version = array._list_available_rest_versions()
    changed = True
    if module.params["suffix"] == "latest":
        all_snaps = array.get_pgroup(
            module.params["name"], snap=True, transfer=True
        ).reverse()
        for snap in all_snaps:
            if not snap["completed"]:
                latest_snap = snap["name"]
                break
        try:
            module.params["suffix"] = latest_snap.split(".")[1]
        except NameError:
            module.fail_json(msg="There is no completed snapshot available.")
    if ":" in module.params["name"] and "::" not in module.params["name"]:
        if get_rpgsnapshot(module, array) is None:
            module.fail_json(
                msg="Selected restore snapshot {0} does not exist in the Protection Group".format(
                    module.params["restore"]
                )
            )
    else:
        if get_pgroupvolume(module, array) is None:
            module.fail_json(
                msg="Selected restore volume {0} does not exist in the Protection Group".format(
                    module.params["restore"]
                )
            )
    volume = (
        module.params["name"]
        + "."
        + module.params["suffix"]
        + "."
        + module.params["restore"]
    )
    if "::" in module.params["target"]:
        target_pod_name = module.params["target"].split(":")[0]
        if "::" in module.params["name"]:
            source_pod_name = module.params["name"].split(":")[0]
        else:
            source_pod_name = ""
        if source_pod_name != target_pod_name:
            if (
                len(array.get_pod(target_pod_name, mediator=True)["arrays"]) > 1
                and POD_SNAPSHOT not in api_version
            ):
                module.fail_json(msg="Volume cannot be restored to a stretched pod")
    if not module.check_mode:
        try:
            array.copy_volume(
                volume, module.params["target"], overwrite=module.params["overwrite"]
            )
        except Exception:
            module.fail_json(
                msg="Failed to restore {0} from pgroup {1}".format(
                    volume, module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def delete_offload_snapshot(module, array):
    """Delete Offloaded Protection Group Snapshot"""
    changed = False
    snapname = module.params["name"] + "." + module.params["suffix"]
    if ":" in module.params["name"] and module.params["offload"]:
        if _check_offload(module, array):
            changed = True
            if not module.check_mode:
                try:
                    array.destroy_pgroup(snapname, on=module.params["offload"])
                    if module.params["eradicate"]:
                        try:
                            array.eradicate_pgroup(
                                snapname, on=module.params["offload"]
                            )
                        except Exception:
                            module.fail_json(
                                msg="Failed to eradicate offloaded snapshot {0} on target {1}".format(
                                    snapname, module.params["offload"]
                                )
                            )
                except Exception:
                    pass
        else:
            module.fail_json(
                msg="Offload target {0} does not exist or not connected".format(
                    module.params["offload"]
                )
            )
    else:
        module.fail_json(msg="Protection Group name not in the correct format")

    module.exit_json(changed=changed)


def delete_pgsnapshot(module, array):
    """Delete Protection Group Snapshot"""
    changed = True
    if not module.check_mode:
        snapname = module.params["name"] + "." + module.params["suffix"]
        try:
            array.destroy_pgroup(snapname)
            if module.params["eradicate"]:
                try:
                    array.eradicate_pgroup(snapname)
                except Exception:
                    module.fail_json(
                        msg="Failed to eradicate pgroup {0}".format(snapname)
                    )
        except Exception:
            module.fail_json(msg="Failed to delete pgroup {0}".format(snapname))
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            suffix=dict(type="str"),
            restore=dict(type="str"),
            offload=dict(type="str"),
            overwrite=dict(type="bool", default=False),
            target=dict(type="str"),
            eradicate=dict(type="bool", default=False),
            now=dict(type="bool", default=False),
            apply_retention=dict(type="bool", default=False),
            remote=dict(type="bool", default=False),
            state=dict(
                type="str", default="present", choices=["absent", "present", "copy"]
            ),
        )
    )

    required_if = [("state", "copy", ["suffix", "restore"])]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )
    pattern = re.compile("^(?=.*[a-zA-Z-])[a-zA-Z0-9]([a-zA-Z0-9-]{0,63}[a-zA-Z0-9])?$")
    state = module.params["state"]
    if state == "present":
        if module.params["suffix"] is None:
            suffix = "snap-" + str(
                (datetime.utcnow() - datetime(1970, 1, 1, 0, 0, 0, 0)).total_seconds()
            )
            module.params["suffix"] = suffix.replace(".", "")
        else:
            if not pattern.match(module.params["suffix"]):
                module.fail_json(
                    msg="Suffix name {0} does not conform to suffix name rules".format(
                        module.params["suffix"]
                    )
                )

    if not module.params["target"] and module.params["restore"]:
        module.params["target"] = module.params["restore"]

    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if OFFLOAD_API not in api_version and module.params["offload"]:
        module.fail_json(
            msg="Minimum version {0} required for offload support".format(OFFLOAD_API)
        )
    pgroup = get_pgroup(module, array)
    if pgroup is None:
        module.fail_json(
            msg="Protection Group {0} does not exist.".format(module.params["name"])
        )
    pgsnap = get_pgsnapshot(module, array)
    if state != "absent" and module.params["offload"]:
        module.fail_json(
            msg="offload parameter not supported for state {0}".format(state)
        )
    elif state == "copy":
        restore_pgsnapvolume(module, array)
    elif state == "present" and not pgsnap:
        create_pgsnapshot(module, array)
    elif state == "present" and pgsnap:
        module.exit_json(changed=False)
    elif (
        state == "absent"
        and module.params["offload"]
        and get_offload_snapshot(module, array)
    ):
        delete_offload_snapshot(module, array)
    elif state == "absent" and pgsnap:
        delete_pgsnapshot(module, array)
    elif state == "absent" and not pgsnap:
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
