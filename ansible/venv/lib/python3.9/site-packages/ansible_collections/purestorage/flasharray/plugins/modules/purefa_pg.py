#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Simon Dodsley (simon@purestorage.com)
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
module: purefa_pg
version_added: '1.0.0'
short_description: Manage protection groups on Pure Storage FlashArrays
description:
- Create, delete or modify protection groups on Pure Storage FlashArrays.
- If a protection group exists and you try to add non-valid types, eg. a host
  to a volume protection group the module will ignore the invalid types.
- Protection Groups on Offload targets are supported.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the protection group.
    type: str
    aliases: [ pgroup ]
    required: true
  state:
    description:
    - Define whether the protection group should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  volume:
    description:
    - List of existing volumes to add to protection group.
    - Note that volume are case-sensitive however FlashArray volume names are unique
      and ignore case - you cannot have I(volumea) and I(volumeA)
    type: list
    elements: str
  host:
    description:
    - List of existing hosts to add to protection group.
    - Note that hostnames are case-sensitive however FlashArray hostnames are unique
      and ignore case - you cannot have I(hosta) and I(hostA)
    type: list
    elements: str
  hostgroup:
    description:
    - List of existing hostgroups to add to protection group.
    - Note that hostgroups are case-sensitive however FlashArray hostgroup names are unique
      and ignore case - you cannot have I(groupa) and I(groupA)
    type: list
    elements: str
  eradicate:
    description:
    - Define whether to eradicate the protection group on delete and leave in trash.
    type : bool
    default: false
  enabled:
    description:
    - Define whether to enabled snapshots for the protection group.
    type : bool
    default: true
  target:
    description:
    - List of remote arrays or offload target for replication protection group
      to connect to.
    - Note that all replicated protection groups are asynchronous.
    - Target arrays or offload targets must already be connected to the source array.
    - Maximum number of targets per Portection Group is 4, assuming your
      configuration suppors this.
    type: list
    elements: str
  rename:
    description:
    - Rename a protection group
    - If the source protection group is in a Pod or Volume Group 'container'
      you only need to provide the new protection group name in the same 'container'
    type: str
  safe_mode:
    description:
    - Enables SafeMode restrictions on the protection group
    - B(Once set disabling this can only be performed by Pure Technical Support)
    type: bool
    default: false
    version_added: '1.13.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new local protection group
  purestorage.flasharray.purefa_pg:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new protection group called bar in pod called foo
  purestorage.flasharray.purefa_pg:
    name: "foo::bar"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new replicated protection group
  purestorage.flasharray.purefa_pg:
    name: foo
    target:
      - arrayb
      - arrayc
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new replicated protection group to offload target and remote array
  purestorage.flasharray.purefa_pg:
    name: foo
    target:
      - offload
      - arrayc
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create new protection group with snapshots disabled
  purestorage.flasharray.purefa_pg:
    name: foo
    enabled: false
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete protection group
  purestorage.flasharray.purefa_pg:
    name: foo
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Eradicate protection group foo on offload target where source array is arrayA
  purestorage.flasharray.purefa_pg:
    name: "arrayA:foo"
    target: offload
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Rename protection group foo in pod arrayA to bar
  purestorage.flasharray.purefa_pg:
    name: "arrayA::foo"
    rename: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create protection group for hostgroups
  purestorage.flasharray.purefa_pg:
    name: bar
    hostgroup:
      - hg1
      - hg2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create protection group for hosts
  purestorage.flasharray.purefa_pg:
    name: bar
    host:
      - host1
      - host2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create replicated protection group for volumes
  purestorage.flasharray.purefa_pg:
    name: bar
    volume:
      - vol1
      - vol2
    target: arrayb
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    get_array,
    purefa_argument_spec,
)

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False


OFFLOAD_API_VERSION = "1.16"
P53_API_VERSION = "1.17"
AC_PG_API_VERSION = "1.13"
RETENTION_LOCK_VERSION = "2.13"


def get_pod(module, array):
    """Get ActiveCluster Pod"""
    pod_name = module.params["name"].split("::")[0]
    try:
        return array.get_pod(pod=pod_name)
    except Exception:
        return None


def get_targets(array):
    """Get Offload Targets"""
    targets = []
    try:
        target_details = array.list_offload()
    except Exception:
        return None

    for targetcnt in range(0, len(target_details)):
        if target_details[targetcnt]["status"] in ["connected", "partially_connected"]:
            targets.append(target_details[targetcnt]["name"])
    return targets


def get_arrays(array):
    """Get Connected Arrays"""
    arrays = []
    array_details = array.list_array_connections()
    api_version = array._list_available_rest_versions()
    for arraycnt in range(0, len(array_details)):
        if P53_API_VERSION in api_version:
            if array_details[arraycnt]["status"] in [
                "connected",
                "partially_connected",
            ]:
                arrays.append(array_details[arraycnt]["array_name"])
        else:
            if array_details[arraycnt]["connected"]:
                arrays.append(array_details[arraycnt]["array_name"])
    return arrays


def get_pending_pgroup(module, array):
    """Get Protection Group"""
    pgroup = None
    if ":" in module.params["name"]:
        if "::" not in module.params["name"]:
            for pgrp in array.list_pgroups(pending=True, on="*"):
                if pgrp["name"].casefold() == module.params["name"].casefold():
                    pgroup = pgrp
                    break
        else:
            for pgrp in array.list_pgroups(pending=True):
                if (
                    pgrp["name"].casefold() == module.params["name"].casefold()
                    and pgrp["time_remaining"]
                ):
                    pgroup = pgrp
                    break
    else:
        for pgrp in array.list_pgroups(pending=True):
            if (
                pgrp["name"].casefold() == module.params["name"].casefold()
                and pgrp["time_remaining"]
            ):
                pgroup = pgrp
                break

    return pgroup


def get_pgroup(module, array):
    """Get Protection Group"""
    pgroup = None
    if ":" in module.params["name"]:
        if "::" not in module.params["name"]:
            for pgrp in array.list_pgroups(on="*"):
                if pgrp["name"].casefold() == module.params["name"].casefold():
                    pgroup = pgrp
                    break
        else:
            for pgrp in array.list_pgroups():
                if pgrp["name"].casefold() == module.params["name"].casefold():
                    pgroup = pgrp
                    break
    else:
        for pgrp in array.list_pgroups():
            if pgrp["name"].casefold() == module.params["name"].casefold():
                pgroup = pgrp
                break

    return pgroup


def get_pgroup_sched(module, array):
    """Get Protection Group Schedule"""
    pgroup = None

    for pgrp in array.list_pgroups(schedule=True):
        if pgrp["name"].casefold() == module.params["name"].casefold():
            pgroup = pgrp
            break

    return pgroup


def check_pg_on_offload(module, array):
    """Check if PG already exists on offload target"""
    array_name = array.get()["array_name"]
    remote_pg = array_name + ":" + module.params["name"]
    targets = get_targets(array)
    for target in targets:
        remote_pgs = array.list_pgroups(pending=True, on=target)
        for rpg in range(0, len(remote_pgs)):
            if remote_pg == remote_pgs[rpg]["name"]:
                return target
    return None


def make_pgroup(module, array):
    """Create Protection Group"""
    changed = True
    if module.params["target"]:
        api_version = array._list_available_rest_versions()
        connected_targets = []
        connected_arrays = get_arrays(array)
        if OFFLOAD_API_VERSION in api_version:
            connected_targets = get_targets(array)
            offload_name = check_pg_on_offload(module, array)
            if offload_name and offload_name in module.params["target"][0:4]:
                module.fail_json(
                    msg="Protection Group {0} already exists on offload target {1}.".format(
                        module.params["name"], offload_name
                    )
                )

        connected_arrays = connected_arrays + connected_targets
        if connected_arrays == []:
            module.fail_json(msg="No connected targets on source array.")
        if set(module.params["target"][0:4]).issubset(connected_arrays):
            if not module.check_mode:
                try:
                    array.create_pgroup(
                        module.params["name"], targetlist=module.params["target"][0:4]
                    )
                except Exception:
                    module.fail_json(
                        msg="Creation of replicated pgroup {0} failed. {1}".format(
                            module.params["name"], module.params["target"][0:4]
                        )
                    )
        else:
            module.fail_json(
                msg="Check all selected targets are connected to the source array."
            )
    else:
        if not module.check_mode:
            try:
                array.create_pgroup(module.params["name"])
            except Exception:
                module.fail_json(
                    msg="Creation of pgroup {0} failed.".format(module.params["name"])
                )
            try:
                if module.params["target"]:
                    array.set_pgroup(
                        module.params["name"],
                        replicate_enabled=module.params["enabled"],
                    )
                else:
                    array.set_pgroup(
                        module.params["name"], snap_enabled=module.params["enabled"]
                    )
            except Exception:
                module.fail_json(
                    msg="Enabling pgroup {0} failed.".format(module.params["name"])
                )
            if module.params["volume"]:
                try:
                    array.set_pgroup(
                        module.params["name"], vollist=module.params["volume"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Adding volumes to pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
            if module.params["host"]:
                try:
                    array.set_pgroup(
                        module.params["name"], hostlist=module.params["host"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Adding hosts to pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
            if module.params["hostgroup"]:
                try:
                    array.set_pgroup(
                        module.params["name"], hgrouplist=module.params["hostgroup"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Adding hostgroups to pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
            if module.params["safe_mode"]:
                arrayv6 = get_array(module)
                try:
                    arrayv6.patch_protection_groups(
                        names=[module.params["name"]],
                        protection_group=flasharray.ProtectionGroup(
                            retention_lock="ratcheted"
                        ),
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to set SafeMode on pgroup {0}".format(
                            module.params["name"]
                        )
                    )
    module.exit_json(changed=changed)


def rename_exists(module, array):
    """Determine if rename target already exists"""
    exists = False
    new_name = module.params["rename"]
    if ":" in module.params["name"]:
        container = module.params["name"].split(":")[0]
        new_name = container + ":" + module.params["rename"]
        if "::" in module.params["name"]:
            new_name = container + "::" + module.params["rename"]
    for pgroup in array.list_pgroups(pending=True):
        if pgroup["name"].casefold() == new_name.casefold():
            exists = True
            break
    return exists


def update_pgroup(module, array):
    """Update Protection Group"""
    changed = renamed = False
    api_version = array._list_available_rest_versions()
    if module.params["target"]:
        connected_targets = []
        connected_arrays = get_arrays(array)

        if OFFLOAD_API_VERSION in api_version:
            connected_targets = get_targets(array)
        connected_arrays = connected_arrays + connected_targets
        if connected_arrays == []:
            module.fail_json(msg="No targets connected to source array.")
        current_connects = array.get_pgroup(module.params["name"])["targets"]
        current_targets = []

        if current_connects:
            for targetcnt in range(0, len(current_connects)):
                current_targets.append(current_connects[targetcnt]["name"])

        if set(module.params["target"][0:4]) != set(current_targets):
            if not set(module.params["target"][0:4]).issubset(connected_arrays):
                module.fail_json(
                    msg="Check all selected targets are connected to the source array."
                )
            changed = True
            if not module.check_mode:
                try:
                    array.set_pgroup(
                        module.params["name"],
                        targetlist=module.params["target"][0:4],
                    )
                except Exception:
                    module.fail_json(
                        msg="Changing targets for pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )

    if (
        module.params["target"]
        and module.params["enabled"]
        != get_pgroup_sched(module, array)["replicate_enabled"]
    ):
        changed = True
        if not module.check_mode:
            try:
                array.set_pgroup(
                    module.params["name"], replicate_enabled=module.params["enabled"]
                )
            except Exception:
                module.fail_json(
                    msg="Changing enabled status of pgroup {0} failed.".format(
                        module.params["name"]
                    )
                )
    elif (
        not module.params["target"]
        and module.params["enabled"] != get_pgroup_sched(module, array)["snap_enabled"]
    ):
        changed = True
        if not module.check_mode:
            try:
                array.set_pgroup(
                    module.params["name"], snap_enabled=module.params["enabled"]
                )
            except Exception:
                module.fail_json(
                    msg="Changing enabled status of pgroup {0} failed.".format(
                        module.params["name"]
                    )
                )

    if (
        module.params["volume"]
        and get_pgroup(module, array)["hosts"] is None
        and get_pgroup(module, array)["hgroups"] is None
    ):
        if get_pgroup(module, array)["volumes"] is None:
            if not module.check_mode:
                changed = True
                try:
                    array.set_pgroup(
                        module.params["name"], vollist=module.params["volume"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Adding volumes to pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
        else:
            cased_vols = list(module.params["volume"])
            cased_pgvols = list(get_pgroup(module, array)["volumes"])
            if not all(x in cased_pgvols for x in cased_vols):
                if not module.check_mode:
                    changed = True
                    try:
                        array.set_pgroup(
                            module.params["name"], addvollist=module.params["volume"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Changing volumes in pgroup {0} failed.".format(
                                module.params["name"]
                            )
                        )

    if (
        module.params["host"]
        and get_pgroup(module, array)["volumes"] is None
        and get_pgroup(module, array)["hgroups"] is None
    ):
        if get_pgroup(module, array)["hosts"] is None:
            if not module.check_mode:
                changed = True
                try:
                    array.set_pgroup(
                        module.params["name"], hostlist=module.params["host"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Adding hosts to pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
        else:
            cased_hosts = list(module.params["host"])
            cased_pghosts = list(get_pgroup(module, array)["hosts"])
            if not all(x in cased_pghosts for x in cased_hosts):
                if not module.check_mode:
                    changed = True
                    try:
                        array.set_pgroup(
                            module.params["name"], addhostlist=module.params["host"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Changing hosts in pgroup {0} failed.".format(
                                module.params["name"]
                            )
                        )

    if (
        module.params["hostgroup"]
        and get_pgroup(module, array)["hosts"] is None
        and get_pgroup(module, array)["volumes"] is None
    ):
        if get_pgroup(module, array)["hgroups"] is None:
            if not module.check_mode:
                changed = True
                try:
                    array.set_pgroup(
                        module.params["name"], hgrouplist=module.params["hostgroup"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Adding hostgroups to pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
        else:
            cased_hostg = list(module.params["hostgroup"])
            cased_pghostg = list(get_pgroup(module, array)["hgroups"])
            if not all(x in cased_pghostg for x in cased_hostg):
                if not module.check_mode:
                    changed = True
                    try:
                        array.set_pgroup(
                            module.params["name"],
                            addhgrouplist=module.params["hostgroup"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Changing hostgroups in pgroup {0} failed.".format(
                                module.params["name"]
                            )
                        )
    if module.params["rename"]:
        if not rename_exists(module, array):
            if ":" in module.params["name"]:
                container = module.params["name"].split(":")[0]
                if "::" in module.params["name"]:
                    rename = container + "::" + module.params["rename"]
                else:
                    rename = container + ":" + module.params["rename"]
            else:
                rename = module.params["rename"]
            renamed = True
            if not module.check_mode:
                try:
                    array.rename_pgroup(module.params["name"], rename)
                    module.params["name"] = rename
                except Exception:
                    module.fail_json(msg="Rename to {0} failed.".format(rename))
        else:
            module.warn(
                "Rename failed. Protection group {0} already exists in container. Continuing with other changes...".format(
                    module.params["rename"]
                )
            )
    if RETENTION_LOCK_VERSION in api_version:
        arrayv6 = get_array(module)
        current_pg = list(
            arrayv6.get_protection_groups(names=[module.params["name"]]).items
        )[0]
        if current_pg.retention_lock == "unlocked" and module.params["safe_mode"]:
            changed = True
            if not module.check_mode:
                res = arrayv6.patch_protection_groups(
                    names=[module.params["name"]],
                    protection_group=flasharray.ProtectionGroup(
                        retention_lock="ratcheted"
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to set SafeMode on protection group {0}. Error: {1}".format(
                            module.params["name"],
                            res.errors[0].message,
                        )
                    )
        if current_pg.retention_lock == "ratcheted" and not module.params["safe_mode"]:
            module.warn(
                "Disabling SafeMode on protection group {0} can only be performed by Pure Technical Support".format(
                    module.params["name"]
                )
            )
    changed = changed or renamed
    module.exit_json(changed=changed)


def eradicate_pgroup(module, array):
    """Eradicate Protection Group"""
    changed = True
    if not module.check_mode:
        if ":" in module.params["name"]:
            if "::" not in module.params["name"]:
                try:
                    target = "".join(module.params["target"])
                    array.destroy_pgroup(
                        module.params["name"], on=target, eradicate=True
                    )
                except Exception:
                    module.fail_json(
                        msg="Eradicating pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
            else:
                try:
                    array.destroy_pgroup(module.params["name"], eradicate=True)
                except Exception:
                    module.fail_json(
                        msg="Eradicating pgroup {0} failed.".format(
                            module.params["name"]
                        )
                    )
        else:
            try:
                array.destroy_pgroup(module.params["name"], eradicate=True)
            except Exception:
                module.fail_json(
                    msg="Eradicating pgroup {0} failed.".format(module.params["name"])
                )
    module.exit_json(changed=changed)


def delete_pgroup(module, array):
    """Delete Protection Group"""
    changed = True
    if not module.check_mode:
        if ":" in module.params["name"]:
            if "::" not in module.params["name"]:
                try:
                    target = "".join(module.params["target"])
                    array.destroy_pgroup(module.params["name"], on=target)
                except Exception:
                    module.fail_json(
                        msg="Deleting pgroup {0} failed.".format(module.params["name"])
                    )
            else:
                try:
                    array.destroy_pgroup(module.params["name"])
                except Exception:
                    module.fail_json(
                        msg="Deleting pgroup {0} failed.".format(module.params["name"])
                    )
        else:
            try:
                array.destroy_pgroup(module.params["name"])
            except Exception:
                module.fail_json(
                    msg="Deleting pgroup {0} failed.".format(module.params["name"])
                )
        if module.params["eradicate"]:
            eradicate_pgroup(module, array)

    module.exit_json(changed=changed)


def recover_pgroup(module, array):
    """Recover deleted protection group"""
    changed = True
    if not module.check_mode:
        if ":" in module.params["name"]:
            if "::" not in module.params["name"]:
                try:
                    target = "".join(module.params["target"])
                    array.recover_pgroup(module.params["name"], on=target)
                except Exception:
                    module.fail_json(
                        msg="Recover pgroup {0} failed.".format(module.params["name"])
                    )
            else:
                try:
                    array.recover_pgroup(module.params["name"])
                except Exception:
                    module.fail_json(
                        msg="Recover pgroup {0} failed.".format(module.params["name"])
                    )
        else:
            try:
                array.recover_pgroup(module.params["name"])
            except Exception:
                module.fail_json(
                    msg="ecover pgroup {0} failed.".format(module.params["name"])
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True, aliases=["pgroup"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            volume=dict(type="list", elements="str"),
            host=dict(type="list", elements="str"),
            hostgroup=dict(type="list", elements="str"),
            target=dict(type="list", elements="str"),
            safe_mode=dict(type="bool", default=False),
            eradicate=dict(type="bool", default=False),
            enabled=dict(type="bool", default=True),
            rename=dict(type="str"),
        )
    )

    mutually_exclusive = [["volume", "host", "hostgroup"]]
    module = AnsibleModule(
        argument_spec, mutually_exclusive=mutually_exclusive, supports_check_mode=True
    )
    if not HAS_PURESTORAGE and module.params["safe_mode"]:
        module.fail_json(
            msg="py-pure-client sdk is required to support 'safe_mode' parameter"
        )

    state = module.params["state"]
    array = get_system(module)
    pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    if module.params["rename"]:
        if not pattern.match(module.params["rename"]):
            module.fail_json(
                msg="Rename value {0} does not conform to naming convention".format(
                    module.params["rename"]
                )
            )
        if not pattern.match(module.params["name"].split(":")[-1]):
            module.fail_json(
                msg="Protection Group name {0} does not conform to naming convention".format(
                    module.params["name"]
                )
            )
    api_version = array._list_available_rest_versions()
    if module.params["safe_mode"] and RETENTION_LOCK_VERSION not in api_version:
        module.fail_json(
            msg="API version does not support setting SafeMode on a protection group."
        )
    if ":" in module.params["name"] and OFFLOAD_API_VERSION not in api_version:
        module.fail_json(msg="API version does not support offload protection groups.")
    if "::" in module.params["name"] and AC_PG_API_VERSION not in api_version:
        module.fail_json(
            msg="API version does not support ActiveCluster protection groups."
        )
    if ":" in module.params["name"]:
        if "::" in module.params["name"]:
            pgname = module.params["name"].split("::")[1]
        else:
            pgname = module.params["name"].split(":")[1]
        if not pattern.match(pgname):
            module.fail_json(
                msg="Protection Group name {0} does not conform to naming convention".format(
                    pgname
                )
            )
    else:
        if not pattern.match(module.params["name"]):
            module.fail_json(
                msg="Protection Group name {0} does not conform to naming convention".format(
                    module.params["name"]
                )
            )

    pgroup = get_pgroup(module, array)
    xpgroup = get_pending_pgroup(module, array)
    if "::" in module.params["name"]:
        if not get_pod(module, array):
            module.fail_json(
                msg="Pod {0} does not exist.".format(
                    module.params["name"].split("::")[0]
                )
            )

    if module.params["host"]:
        try:
            for hst in module.params["host"]:
                array.get_host(hst)
        except Exception:
            module.fail_json(msg="Host {0} not found".format(hst))

    if module.params["hostgroup"]:
        try:
            for hstg in module.params["hostgroup"]:
                array.get_hgroup(hstg)
        except Exception:
            module.fail_json(msg="Hostgroup {0} not found".format(hstg))

    if pgroup and state == "present":
        update_pgroup(module, array)
    elif pgroup and state == "absent":
        delete_pgroup(module, array)
    elif xpgroup and state == "absent" and module.params["eradicate"]:
        eradicate_pgroup(module, array)
    elif (
        not pgroup
        and not xpgroup
        and state == "present"
        and not module.params["rename"]
    ):
        make_pgroup(module, array)
    elif not pgroup and state == "present" and module.params["rename"]:
        module.exit_json(changed=False)
    elif xpgroup and state == "present":
        recover_pgroup(module, array)
    elif pgroup is None and state == "absent":
        module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
