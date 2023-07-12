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
module: purefa_vg
version_added: '1.0.0'
short_description: Manage volume groups on Pure Storage FlashArrays
description:
- Create, delete or modify volume groups on Pure Storage FlashArrays.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the volume group.
    - Multi-volume-group support available from Purity//FA 6.0.0
      B(***NOTE***) Manual deletion or eradication of individual volume groups created
      using multi-volume-group will cause idempotency to fail
    - Multi-volume-group support only exists for volume group creation
    type: str
    required: true
  state:
    description:
    - Define whether the volume group should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  eradicate:
    description:
    - Define whether to eradicate the volume group on delete and leave in trash.
    type : bool
    default: false
  bw_qos:
    description:
    - Bandwidth limit for vgroup in M or G units.
      M will set MB/s
      G will set GB/s
      To clear an existing QoS setting use 0 (zero)
    type: str
  iops_qos:
    description:
    - IOPs limit for vgroup - use value or K or M
      K will mean 1000
      M will mean 1000000
      To clear an existing IOPs setting use 0 (zero)
    type: str
  count:
    description:
    - Number of volume groups to be created in a multiple volume group creation
    - Only supported from Purity//FA v6.0.0 and higher
    type: int
  start:
    description:
    - Number at which to start the multiple volume group creation index
    - Only supported from Purity//FA v6.0.0 and higher
    type: int
    default: 0
  digits:
    description:
    - Number of digits to use for multiple volume group count. This
      will pad the index number with zeros where necessary
    - Only supported from Purity//FA v6.0.0 and higher
    - Range is between 1 and 10
    type: int
    default: 1
  suffix:
    description:
    - Suffix string, if required, for multiple volume group create
    - Volume group names will be formed as I(<name>#I<suffix>), where
      I(#) is a placeholder for the volume index
      See associated descriptions
    - Only supported from Purity//FA v6.0.0 and higher
    type: str
  priority_operator:
    description:
    - DMM Priority Adjustment operator
    type: str
    choices: [ +, '-' ]
    default: +
    version_added: '1.13.0'
  priority_value:
    description:
    - DMM Priority Adjustment value
    type: int
    choices: [ 0, 10 ]
    default: 0
    version_added: '1.13.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new volune group
  purestorage.flasharray.purefa_vg:
    name: foo
    bw_qos: 50M
    iops_qos: 100
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create 10 volune groups of pattern foo#bar with QoS
  purestorage.flasharray.purefa_vg:
    name: foo
    suffix: bar
    count: 10
    start: 10
    digits: 3
    bw_qos: 50M
    iops_qos: 100
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update volune group QoS limits
  purestorage.flasharray.purefa_vg:
    name: foo
    bw_qos: 0
    iops_qos: 5555
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update volune group DMM Priority Adjustment (Purity//FA 6.1.2+)
  purestorage.flasharray.purefa_vg:
    name: foo
    priority_operator: '-'
    priority_value: 10
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Destroy volume group
  purestorage.flasharray.purefa_vg:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Recover deleted volune group - no changes are made to the volume group on recovery
  purestorage.flasharray.purefa_vg:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Destroy and Eradicate volume group
  purestorage.flasharray.purefa_vg:
    name: foo
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    get_system,
    purefa_argument_spec,
)


VGROUP_API_VERSION = "1.13"
VG_IOPS_VERSION = "1.17"
MULTI_VG_VERSION = "2.2"
PRIORITY_API_VERSION = "2.11"


def human_to_bytes(size):
    """Given a human-readable byte string (e.g. 2G, 30M),
    return the number of bytes.  Will return 0 if the argument has
    unexpected form.
    """
    bytes = size[:-1]
    unit = size[-1].upper()
    if bytes.isdigit():
        bytes = int(bytes)
        if unit == "P":
            bytes *= 1125899906842624
        elif unit == "T":
            bytes *= 1099511627776
        elif unit == "G":
            bytes *= 1073741824
        elif unit == "M":
            bytes *= 1048576
        elif unit == "K":
            bytes *= 1024
        else:
            bytes = 0
    else:
        bytes = 0
    return bytes


def human_to_real(iops):
    """Given a human-readable IOPs string (e.g. 2K, 30M),
    return the real number.  Will return 0 if the argument has
    unexpected form.
    """
    digit = iops[:-1]
    unit = iops[-1].upper()
    if unit.isdigit():
        digit = iops
    elif digit.isdigit():
        digit = int(digit)
        if unit == "M":
            digit *= 1000000
        elif unit == "K":
            digit *= 1000
        else:
            digit = 0
    else:
        digit = 0
    return digit


def get_multi_vgroups(module, destroyed=False):
    """Return True is all volume groups exist or None"""
    names = []
    array = get_array(module)
    for vg_num in range(
        module.params["start"], module.params["count"] + module.params["start"]
    ):
        names.append(
            module.params["name"]
            + str(vg_num).zfill(module.params["digits"])
            + module.params["suffix"]
        )
    return bool(
        array.get_volume_groups(names=names, destroyed=destroyed).status_code == 200
    )


def get_pending_vgroup(module, array):
    """Get Deleted Volume Group"""
    vgroup = None
    for vgrp in array.list_vgroups(pending=True):
        if vgrp["name"] == module.params["name"] and vgrp["time_remaining"]:
            vgroup = vgrp
            break

    return vgroup


def get_vgroup(module, array):
    """Get Volume Group"""
    vgroup = None
    for vgrp in array.list_vgroups():
        if vgrp["name"] == module.params["name"]:
            vgroup = vgrp
            break

    return vgroup


def make_vgroup(module, array):
    """Create Volume Group"""
    changed = True
    api_version = array._list_available_rest_versions()
    if (
        module.params["bw_qos"]
        or module.params["iops_qos"]
        and VG_IOPS_VERSION in api_version
    ):
        if module.params["bw_qos"] and not module.params["iops_qos"]:
            if int(human_to_bytes(module.params["bw_qos"])) in range(
                1048576, 549755813888
            ):
                changed = True
                if not module.check_mode:
                    try:
                        array.create_vgroup(
                            module.params["name"],
                            bandwidth_limit=module.params["bw_qos"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} creation failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(
                    msg="Bandwidth QoS value {0} out of range.".format(
                        module.params["bw_qos"]
                    )
                )
        elif module.params["iops_qos"] and not module.params["bw_qos"]:
            if int(human_to_real(module.params["iops_qos"])) in range(100, 100000000):
                changed = True
                if not module.check_mode:
                    try:
                        array.create_vgroup(
                            module.params["name"], iops_limit=module.params["iops_qos"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} creation failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(
                    msg="IOPs QoS value {0} out of range.".format(
                        module.params["iops_qos"]
                    )
                )
        else:
            bw_qos_size = int(human_to_bytes(module.params["bw_qos"]))
            if int(human_to_real(module.params["iops_qos"])) in range(
                100, 100000000
            ) and bw_qos_size in range(1048576, 549755813888):
                changed = True
                if not module.check_mode:
                    try:
                        array.create_vgroup(
                            module.params["name"],
                            iops_limit=module.params["iops_qos"],
                            bandwidth_limit=module.params["bw_qos"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} creation failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(msg="IOPs or Bandwidth QoS value out of range.")
    else:
        changed = True
        if not module.check_mode:
            try:
                array.create_vgroup(module.params["name"])
            except Exception:
                module.fail_json(
                    msg="creation of volume group {0} failed.".format(
                        module.params["name"]
                    )
                )
    if PRIORITY_API_VERSION in api_version:
        array = get_array(module)
        volume_group = flasharray.VolumeGroup(
            priority_adjustment=flasharray.PriorityAdjustment(
                priority_adjustment_operator=module.params["priority_operator"],
                priority_adjustment_value=module.params["priority_value"],
            ),
        )
        if not module.check_mode:
            res = array.patch_volume_groups(
                names=[module.params["name"]], volume_group=volume_group
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to set priority adjustment for volume group {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )

    module.exit_json(changed=changed)


def make_multi_vgroups(module, array):
    """Create multiple Volume Groups"""
    changed = True
    bw_qos_size = iops_qos_size = 0
    names = []
    api_version = array._list_available_rest_versions()
    array = get_array(module)
    for vg_num in range(
        module.params["start"], module.params["count"] + module.params["start"]
    ):
        names.append(
            module.params["name"]
            + str(vg_num).zfill(module.params["digits"])
            + module.params["suffix"]
        )
    if module.params["bw_qos"]:
        bw_qos = int(human_to_bytes(module.params["bw_qos"]))
        if bw_qos in range(1048576, 549755813888):
            bw_qos_size = bw_qos
        else:
            module.fail_json(msg="Bandwidth QoS value out of range.")
    if module.params["iops_qos"]:
        iops_qos = int(human_to_real(module.params["iops_qos"]))
        if iops_qos in range(100, 100000000):
            iops_qos_size = iops_qos
        else:
            module.fail_json(msg="IOPs QoS value out of range.")
    if bw_qos_size != 0 and iops_qos_size != 0:
        volume_group = flasharray.VolumeGroupPost(
            qos=flasharray.Qos(bandwidth_limit=bw_qos_size, iops_limit=iops_qos_size)
        )
    elif bw_qos_size == 0 and iops_qos_size == 0:
        volume_group = flasharray.VolumeGroupPost()
    elif bw_qos_size == 0 and iops_qos_size != 0:
        volume_group = flasharray.VolumeGroupPost(
            qos=flasharray.Qos(iops_limit=iops_qos_size)
        )
    elif bw_qos_size != 0 and iops_qos_size == 0:
        volume_group = flasharray.VolumeGroupPost(
            qos=flasharray.Qos(bandwidth_limit=bw_qos_size)
        )
    if not module.check_mode:
        res = array.post_volume_groups(names=names, volume_group=volume_group)
        if res.status_code != 200:
            module.fail_json(
                msg="Multi-Vgroup {0}#{1} creation failed: {2}".format(
                    module.params["name"],
                    module.params["suffix"],
                    res.errors[0].message,
                )
            )
        if PRIORITY_API_VERSION in api_version:
            volume_group = flasharray.VolumeGroup(
                priority_adjustment=flasharray.PriorityAdjustment(
                    priority_adjustment_operator=module.params["priority_operator"],
                    priority_adjustment_value=module.params["priority_value"],
                ),
            )
            res = array.patch_volume_groups(names=names, volume_group=volume_group)
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to set priority adjustments for multi-vgroup {0}#{1}. Error: {2}".format(
                        module.params["name"],
                        module.params["suffix"],
                        res.errors[0].message,
                    )
                )
    module.exit_json(changed=changed)


def update_vgroup(module, array):
    """Update Volume Group"""
    changed = False
    api_version = array._list_available_rest_versions()
    if PRIORITY_API_VERSION in api_version:
        arrayv6 = get_array(module)
        vg_prio = list(arrayv6.get_volume_groups(names=[module.params["name"]]).items)[
            0
        ].priority_adjustment
        if (
            module.params["priority_operator"]
            and vg_prio.priority_adjustment_operator
            != module.params["priority_operator"]
        ):
            changed = True
            new_operator = module.params["priority_operator"]
        else:
            new_operator = vg_prio.priority_adjustment_operator
        if vg_prio.priority_adjustment_value != module.params["priority_value"]:
            changed = True
            new_value = module.params["priority_value"]
        else:
            new_value = vg_prio.priority_adjustment_value
        if changed and not module.check_mode:
            volume_group = flasharray.VolumeGroup(
                priority_adjustment=flasharray.PriorityAdjustment(
                    priority_adjustment_operator=new_operator,
                    priority_adjustment_value=new_value,
                )
            )
            res = arrayv6.patch_volume_groups(
                names=[module.params["name"]], volume_group=volume_group
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to changfe DMM Priority for volume group {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )
    if VG_IOPS_VERSION in api_version:
        try:
            vg_qos = array.get_vgroup(module.params["name"], qos=True)
        except Exception:
            module.fail_json(
                msg="Failed to get QoS settings for vgroup {0}.".format(
                    module.params["name"]
                )
            )
    if VG_IOPS_VERSION in api_version:
        if vg_qos["bandwidth_limit"] is None:
            vg_qos["bandwidth_limit"] = 0
        if vg_qos["iops_limit"] is None:
            vg_qos["iops_limit"] = 0
    if module.params["bw_qos"] and VG_IOPS_VERSION in api_version:
        if human_to_bytes(module.params["bw_qos"]) != vg_qos["bandwidth_limit"]:
            if module.params["bw_qos"] == "0":
                changed = True
                if not module.check_mode:
                    try:
                        array.set_vgroup(module.params["name"], bandwidth_limit="")
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} Bandwidth QoS removal failed.".format(
                                module.params["name"]
                            )
                        )
            elif int(human_to_bytes(module.params["bw_qos"])) in range(
                1048576, 549755813888
            ):
                changed = True
                if not module.check_mode:
                    try:
                        array.set_vgroup(
                            module.params["name"],
                            bandwidth_limit=module.params["bw_qos"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} Bandwidth QoS change failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(
                    msg="Bandwidth QoS value {0} out of range.".format(
                        module.params["bw_qos"]
                    )
                )
    if module.params["iops_qos"] and VG_IOPS_VERSION in api_version:
        if human_to_real(module.params["iops_qos"]) != vg_qos["iops_limit"]:
            if module.params["iops_qos"] == "0":
                changed = True
                if not module.check_mode:
                    try:
                        array.set_vgroup(module.params["name"], iops_limit="")
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} IOPs QoS removal failed.".format(
                                module.params["name"]
                            )
                        )
            elif int(human_to_real(module.params["iops_qos"])) in range(100, 100000000):
                changed = True
                if not module.check_mode:
                    try:
                        array.set_vgroup(
                            module.params["name"], iops_limit=module.params["iops_qos"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Vgroup {0} IOPs QoS change failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(
                    msg="Bandwidth QoS value {0} out of range.".format(
                        module.params["bw_qos"]
                    )
                )

    module.exit_json(changed=changed)


def recover_vgroup(module, array):
    """Recover Volume Group"""
    changed = True
    if not module.check_mode:
        try:
            array.recover_vgroup(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Recovery of volume group {0} failed.".format(module.params["name"])
            )

    module.exit_json(changed=changed)


def eradicate_vgroup(module, array):
    """Eradicate Volume Group"""
    changed = True
    if not module.check_mode:
        try:
            array.eradicate_vgroup(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Eradicating vgroup {0} failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def delete_vgroup(module, array):
    """Delete Volume Group"""
    changed = True
    if not module.check_mode:
        try:
            array.destroy_vgroup(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Deleting vgroup {0} failed.".format(module.params["name"])
            )
    if module.params["eradicate"]:
        eradicate_vgroup(module, array)

    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            bw_qos=dict(type="str"),
            iops_qos=dict(type="str"),
            count=dict(type="int"),
            start=dict(type="int", default=0),
            digits=dict(type="int", default=1),
            suffix=dict(type="str"),
            priority_operator=dict(type="str", choices=["+", "-"], default="+"),
            priority_value=dict(type="int", choices=[0, 10], default=0),
            eradicate=dict(type="bool", default=False),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if VGROUP_API_VERSION not in api_version:
        module.fail_json(msg="API version does not support volume groups.")

    vgroup = get_vgroup(module, array)
    xvgroup = get_pending_vgroup(module, array)

    if module.params["count"]:
        if not HAS_PURESTORAGE:
            module.fail_json(
                msg="py-pure-client sdk is required to support 'count' parameter"
            )
        if MULTI_VG_VERSION not in api_version:
            module.fail_json(
                msg="'count' parameter is not supported until Purity//FA 6.0.0 or higher"
            )
        if module.params["digits"] and module.params["digits"] not in range(1, 10):
            module.fail_json(msg="'digits' must be in the range of 1 to 10")
        if module.params["start"] < 0:
            module.fail_json(msg="'start' must be a positive number")
        vgroup = get_multi_vgroups(module)
        if state == "present" and not vgroup:
            make_multi_vgroups(module, array)
        elif state == "absent" and not vgroup:
            module.exit_json(changed=False)
        else:
            module.warn("Method not yet supported for multi-vgroup")
    else:
        if xvgroup and state == "present":
            recover_vgroup(module, array)
        elif vgroup and state == "absent":
            delete_vgroup(module, array)
        elif xvgroup and state == "absent" and module.params["eradicate"]:
            eradicate_vgroup(module, array)
        elif not vgroup and not xvgroup and state == "present":
            make_vgroup(module, array)
        elif vgroup and state == "present":
            update_vgroup(module, array)
        elif vgroup is None and state == "absent":
            module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
