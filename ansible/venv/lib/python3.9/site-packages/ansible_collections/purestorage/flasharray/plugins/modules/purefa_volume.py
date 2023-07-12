#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
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
module: purefa_volume
version_added: '1.0.0'
short_description:  Manage volumes on Pure Storage FlashArrays
description:
- Create, delete or extend the capacity of a volume on Pure Storage FlashArray.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the volume.
    - Volume could be created in a POD with this syntax POD_NAME::VOLUME_NAME.
    - Volume could be created in a volume group with this syntax VG_NAME/VOLUME_NAME.
    - Multi-volume support available from Purity//FA 6.0.0
      B(***NOTE***) Manual deletion or eradication of individual volumes created
      using multi-volume will cause idempotency to fail
    - Multi-volume support only exists for volume creation
    type: str
    required: true
  target:
    description:
    - The name of the target volume, if copying.
    type: str
  state:
    description:
    - Define whether the volume should exist or not.
    default: present
    choices: [ absent, present ]
    type: str
  eradicate:
    description:
    - Define whether to eradicate the volume on delete or leave in trash.
    type: bool
    default: false
  overwrite:
    description:
    - Define whether to overwrite a target volume if it already exisits.
    type: bool
    default: false
  size:
    description:
    - Volume size in M, G, T or P units.
    type: str
  count:
    description:
    - Number of volumes to be created in a multiple volume creation
    - Only supported from Purity//FA v6.0.0 and higher
    type: int
  start:
    description:
    - Number at which to start the multiple volume creation index
    - Only supported from Purity//FA v6.0.0 and higher
    type: int
    default: 0
  digits:
    description:
    - Number of digits to use for multiple volume count. This
      will pad the index number with zeros where necessary
    - Only supported from Purity//FA v6.0.0 and higher
    - Range is between 1 and 10
    type: int
    default: 1
  suffix:
    description:
    - Suffix string, if required, for multiple volume create
    - Volume names will be formed as I(<name>#I<suffix>), where
      I(#) is a placeholder for the volume index
      See associated descriptions
    - Only supported from Purity//FA v6.0.0 and higher
    type: str
  bw_qos:
    description:
    - Bandwidth limit for volume in M or G units.
      M will set MB/s
      G will set GB/s
      To clear an existing QoS setting use 0 (zero)
    type: str
    aliases: [ qos ]
  iops_qos:
    description:
    - IOPs limit for volume - use value or K or M
      K will mean 1000
      M will mean 1000000
      To clear an existing IOPs setting use 0 (zero)
    type: str
  move:
    description:
    - Move a volume in and out of a pod or vgroup
    - Provide the name of pod or vgroup to move the volume to
    - Pod and Vgroup names must be unique in the array
    - To move to the local array, specify C(local)
    - This is not idempotent - use C(ignore_errors) in the play
    type: str
  rename:
    description:
    - Value to rename the specified volume to.
    - Rename only applies to the container the current volumes is in.
    - There is no requirement to specify the pod or vgroup name as this is implied.
    type: str
  pgroup:
    description:
    - Name of exisitng, not deleted, protection group to add volume to
    - Only application for volume(s) creation
    - Superceeded from Purity//FA 6.3.4 by I(add_to_pgs)
    type: str
    version_added: 1.8.0
  priority_operator:
    description:
    - DMM Priority Adjustment operator
    type: str
    choices: [ '=', '+', '-' ]
    version_added: '1.13.0'
  priority_value:
    description:
    - DMM Priority Adjustment value
    type: int
    choices: [ -10, 0, 10 ]
    version_added: '1.13.0'
  with_default_protection:
    description:
    - Whether to add the default container protection groups to
      those specified in I(add_to_pgs) as the inital protection
      of a new volume.
    type: bool
    default: true
    version_added: '1.14.0'
  add_to_pgs:
    description:
    - A new volume will be added to the specified protection groups
      on creation
    type: list
    elements: str
    version_added: '1.14.0'
  promotion_state:
    description:
    - Promote or demote the volume so that the volume starts or
      stops accepting write requests.
    type: str
    choices: [ promoted, demoted ]
    version_added: '1.16.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new volume named foo with a QoS limit
  purestorage.flasharray.purefa_volume:
    name: foo
    size: 1T
    bw_qos: 58M
    iops_qos: 23K
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create new volume named foo with a DMM priority (Purity//FA 6.1.2+)
  purestorage.flasharray.purefa_volume:
    name: foo
    size: 1T
    priority_operator: +
    priorty_value: 10
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create new volume named foo in pod bar in protection group pg1
  purestorage.flasharray.purefa_volume:
    name: bar::foo
    prgoup: pg1
    size: 1T
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Create 10 volumes with index starting at 10 but padded with 3 digits
  purestorage.flasharray.purefa_volume:
    name: foo
    size: 1T
    suffix: bar
    count: 10
    start: 10
    digits: 3
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Extend the size of an existing volume named foo
  purestorage.flasharray.purefa_volume:
    name: foo
    size: 2T
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Delete and eradicate volume named foo
  purestorage.flasharray.purefa_volume:
    name: foo
    eradicate: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Create clone of volume bar named foo
  purestorage.flasharray.purefa_volume:
    name: foo
    target: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Overwrite volume bar with volume foo
  purestorage.flasharray.purefa_volume:
    name: foo
    target: bar
    overwrite: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Clear volume QoS from volume foo
  purestorage.flasharray.purefa_volume:
    name: foo
    bw_qos: 0
    iops_qos: 0
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Move local volume foo from local array to pod bar
  purestorage.flasharray.purefa_volume:
    name: foo
    move: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Move volume foo in pod bar to local array
  purestorage.flasharray.purefa_volume:
    name: bar::foo
    move: local
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Move volume foo in pod bar to vgroup fin
  purestorage.flasharray.purefa_volume:
    name: bar::foo
    move: fin
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
volume:
    description: A dictionary describing the changed volume.  Only some
        attributes below will be returned with various actions.
    type: dict
    returned: success
    contains:
        source:
            description: Volume name of source volume used for volume copy
            type: str
        serial:
            description: Volume serial number
            type: str
            sample: '361019ECACE43D83000120A4'
        nvme_nguid:
            description: Volume NVMe namespace globally unique identifier
            type: str
            sample: 'eui.00cd6b99ef25864724a937c5000be684'
        page83_naa:
            description: Volume NAA canonical name
            type: str
            sample: 'naa.624a9370361019ecace43db3000120a4'
        created:
            description: Volume creation time
            type: str
            sample: '2019-03-13T22:49:24Z'
        name:
            description: Volume name
            type: str
        size:
            description: Volume size in bytes
            type: int
        bandwidth_limit:
            description: Volume bandwidth limit in bytes/sec
            type: int
        iops_limit:
            description: Volume IOPs limit
            type: int
        priority_operator:
            description: DMM Priority Adjustment operator
            type: str
        priority_value:
            description: DMM Priority Adjustment value
            type: int
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

import re
import time
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    get_system,
    purefa_argument_spec,
)


QOS_API_VERSION = "1.14"
VGROUPS_API_VERSION = "1.13"
POD_API_VERSION = "1.13"
AC_QOS_VERSION = "1.16"
OFFLOAD_API_VERSION = "1.16"
IOPS_API_VERSION = "1.17"
MULTI_VOLUME_VERSION = "2.2"
PROMOTE_API_VERSION = "1.19"
PURE_OUI = "naa.624a9370"
PRIORITY_API_VERSION = "2.11"
DEFAULT_API_VERSION = "2.16"
VOLUME_PROMOTION_API_VERSION = "2.2"


def _create_nguid(serial):
    nguid = "eui.00" + serial[0:14] + "24a937" + serial[-10:]
    return nguid


def get_pod(module, array):
    """Get ActiveCluster Pod"""
    pod_name = module.params["pgroup"].split("::")[0]
    try:
        return array.get_pod(pod=pod_name)
    except Exception:
        return None


def get_pending_pgroup(module, array):
    """Get Protection Group"""
    pgroup = None
    if ":" in module.params["pgroup"]:
        if "::" not in module.params["pgroup"]:
            for pgrp in array.list_pgroups(pending=True, on="*"):
                if pgrp["name"] == module.params["pgroup"] and pgrp["time_remaining"]:
                    pgroup = pgrp
                    break
        else:
            for pgrp in array.list_pgroups(pending=True):
                if pgrp["name"] == module.params["pgroup"] and pgrp["time_remaining"]:
                    pgroup = pgrp
                    break
    else:
        for pgrp in array.list_pgroups(pending=True):
            if pgrp["name"] == module.params["pgroup"] and pgrp["time_remaining"]:
                pgroup = pgrp
                break

    return pgroup


def get_pgroup(module, array):
    """Get Protection Group"""
    pgroup = None
    if ":" in module.params["pgroup"]:
        if "::" not in module.params["pgroup"]:
            for pgrp in array.list_pgroups(on="*"):
                if pgrp["name"] == module.params["pgroup"]:
                    pgroup = pgrp
                    break
        else:
            for pgrp in array.list_pgroups():
                if pgrp["name"] == module.params["pgroup"]:
                    pgroup = pgrp
                    break
    else:
        for pgrp in array.list_pgroups():
            if pgrp["name"] == module.params["pgroup"]:
                pgroup = pgrp
                break

    return pgroup


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


def get_multi_volumes(module, destroyed=False):
    """Return True is all volumes exist or None"""
    names = []
    array = get_array(module)
    for vol_num in range(
        module.params["start"], module.params["count"] + module.params["start"]
    ):
        names.append(
            module.params["name"]
            + str(vol_num).zfill(module.params["digits"])
            + module.params["suffix"]
        )
    return bool(array.get_volumes(names=names, destroyed=destroyed).status_code == 200)


def get_volume(module, array):
    """Return Volume or None"""
    try:
        return array.get_volume(module.params["name"])
    except Exception:
        return None


def get_endpoint(name, array):
    """Return Endpoint or None"""
    try:
        return array.get_volume(name, pending=True, protocol_endpoint=True)
    except Exception:
        return None


def get_destroyed_volume(vol, array):
    """Return Destroyed Volume or None"""
    try:
        return bool(array.get_volume(vol, pending=True)["time_remaining"] != "")
    except Exception:
        return False


def get_destroyed_endpoint(vol, array):
    """Return Destroyed Endpoint or None"""
    try:
        return bool(
            array.get_volume(vol, protocol_endpoint=True, pending=True)[
                "time_remaining"
            ]
            != ""
        )
    except Exception:
        return False


def get_target(module, array):
    """Return Volume or None"""
    try:
        return array.get_volume(module.params["target"])
    except Exception:
        return None


def check_vgroup(module, array):
    """Check is the requested VG to create volume in exists"""
    vg_exists = False
    api_version = array._list_available_rest_versions()
    if VGROUPS_API_VERSION in api_version:
        vg_name = module.params["name"].split("/")[0]
        try:
            vgs = array.list_vgroups()
        except Exception:
            module.fail_json(msg="Failed to get volume groups list. Check array.")
        for vgroup in range(0, len(vgs)):
            if vg_name == vgs[vgroup]["name"]:
                vg_exists = True
                break
    else:
        module.fail_json(
            msg="VG volumes are not supported. Please upgrade your FlashArray."
        )
    return vg_exists


def check_pod(module, array):
    """Check is the requested pod to create volume in exists"""
    pod_exists = False
    api_version = array._list_available_rest_versions()
    if POD_API_VERSION in api_version:
        pod_name = module.params["name"].split("::")[0]
        try:
            pods = array.list_pods()
        except Exception:
            module.fail_json(msg="Failed to get pod list. Check array.")
        for pod in range(0, len(pods)):
            if pod_name == pods[pod]["name"]:
                pod_exists = True
                break
    else:
        module.fail_json(
            msg="Pod volumes are not supported. Please upgrade your FlashArray."
        )
    return pod_exists


def create_volume(module, array):
    """Create Volume"""
    volfact = []
    changed = False
    api_version = array._list_available_rest_versions()
    if "/" in module.params["name"] and not check_vgroup(module, array):
        module.fail_json(
            msg="Failed to create volume {0}. Volume Group does not exist.".format(
                module.params["name"]
            )
        )
    if "::" in module.params["name"]:
        if not check_pod(module, array):
            module.fail_json(
                msg="Failed to create volume {0}. Pod does not exist".format(
                    module.params["name"]
                )
            )
        pod_name = module.params["name"].split("::")[0]
        if PROMOTE_API_VERSION in api_version:
            if array.get_pod(pod_name)["promotion_status"] == "demoted":
                module.fail_json(msg="Volume cannot be created in a demoted pod")
        if module.params["bw_qos"] or module.params["iops_qos"]:
            if AC_QOS_VERSION not in api_version:
                module.warn(
                    "Pods cannot cannot contain volumes with QoS settings. Ignoring..."
                )
                module.params["bw_qos"] = module.params["iops_qos"] = None
    if not module.params["size"]:
        module.fail_json(msg="Size for a new volume must be specified")
    if module.params["bw_qos"] or module.params["iops_qos"]:
        if module.params["bw_qos"] and QOS_API_VERSION in api_version:
            if module.params["iops_qos"] and IOPS_API_VERSION in api_version:
                if module.params["bw_qos"] and not module.params["iops_qos"]:
                    if int(human_to_bytes(module.params["bw_qos"])) in range(
                        1048576, 549755813888
                    ):
                        changed = True
                        if not module.check_mode:
                            try:
                                volfact = array.create_volume(
                                    module.params["name"],
                                    module.params["size"],
                                    bandwidth_limit=module.params["bw_qos"],
                                )
                                volfact["page83_naa"] = (
                                    PURE_OUI + volfact["serial"].lower()
                                )
                                volfact["nvme_nguid"] = _create_nguid(
                                    volfact["serial"].lower()
                                )
                            except Exception:
                                module.fail_json(
                                    msg="Volume {0} creation failed.".format(
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
                    if (
                        100000000
                        >= int(human_to_real(module.params["iops_qos"]))
                        >= 100
                    ):
                        changed = True
                        if not module.check_mode:
                            try:
                                volfact = array.create_volume(
                                    module.params["name"],
                                    module.params["size"],
                                    iops_limit=module.params["iops_qos"],
                                )
                                volfact["page83_naa"] = (
                                    PURE_OUI + volfact["serial"].lower()
                                )
                                volfact["nvme_nguid"] = _create_nguid(
                                    volfact["serial"].lower()
                                )
                            except Exception:
                                module.fail_json(
                                    msg="Volume {0} creation failed.".format(
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
                                volfact = array.create_volume(
                                    module.params["name"],
                                    module.params["size"],
                                    iops_limit=module.params["iops_qos"],
                                    bandwidth_limit=module.params["bw_qos"],
                                )
                                volfact["page83_naa"] = (
                                    PURE_OUI + volfact["serial"].lower()
                                )
                                volfact["nvme_nguid"] = _create_nguid(
                                    volfact["serial"].lower()
                                )
                            except Exception:
                                module.fail_json(
                                    msg="Volume {0} creation failed.".format(
                                        module.params["name"]
                                    )
                                )
                    else:
                        module.fail_json(
                            msg="IOPs or Bandwidth QoS value out of range."
                        )
            else:
                if module.params["bw_qos"]:
                    if int(human_to_bytes(module.params["bw_qos"])) in range(
                        1048576, 549755813888
                    ):
                        changed = True
                        if not module.check_mode:
                            try:
                                volfact = array.create_volume(
                                    module.params["name"],
                                    module.params["size"],
                                    bandwidth_limit=module.params["bw_qos"],
                                )
                                volfact["page83_naa"] = (
                                    PURE_OUI + volfact["serial"].lower()
                                )
                                volfact["nvme_nguid"] = _create_nguid(
                                    volfact["serial"].lower()
                                )
                            except Exception:
                                module.fail_json(
                                    msg="Volume {0} creation failed.".format(
                                        module.params["name"]
                                    )
                                )
                    else:
                        module.fail_json(
                            msg="Bandwidth QoS value {0} out of range.".format(
                                module.params["bw_qos"]
                            )
                        )
                else:
                    changed = True
                    if not module.check_mode:
                        try:
                            volfact = array.create_volume(
                                module.params["name"], module.params["size"]
                            )
                            volfact["page83_naa"] = PURE_OUI + volfact["serial"].lower()
                            volfact["nvme_nguid"] = _create_nguid(
                                volfact["serial"].lower()
                            )
                        except Exception:
                            module.fail_json(
                                msg="Volume {0} creation failed.".format(
                                    module.params["name"]
                                )
                            )
    else:
        changed = True
        if not module.check_mode:
            try:
                volfact = array.create_volume(
                    module.params["name"], module.params["size"]
                )
                volfact["page83_naa"] = PURE_OUI + volfact["serial"].lower()
                volfact["nvme_nguid"] = _create_nguid(volfact["serial"].lower())
            except Exception:
                module.fail_json(
                    msg="Volume {0} creation failed.".format(module.params["name"])
                )
    if VOLUME_PROMOTION_API_VERSION in api_version and module.params["promotion_state"]:
        arrayv6 = get_array(module)
        volume = flasharray.VolumePatch(
            requested_promotion_state=module.params["promotion_state"]
        )
        changed = True
        if not module.check_mode:
            res = arrayv6.patch_volumes(names=[module.params["name"]], volume=volume)
            if res.status_code != 200:
                arrayv6.patch_volumes(
                    names=[module.params["name"]],
                    volume=flasharray.VolumePatch(destroyed=True),
                )
                arrayv6.delete_volumes(names=[module.params["name"]])
                module.fail_json(
                    msg="Failed to set Promotion State for volume {0}.".format(
                        module.params["name"]
                    )
                )
            else:
                volfact["promotion_state"] = module.params["promotion_state"]
    if PRIORITY_API_VERSION in api_version and module.params["priority_operator"]:
        arrayv6 = get_array(module)
        volume = flasharray.VolumePatch(
            priority_adjustment=flasharray.PriorityAdjustment(
                priority_adjustment_operator=module.params["priority_operator"],
                priority_adjustment_value=module.params["priority_value"],
            )
        )
        res = arrayv6.patch_volumes(names=[module.params["name"]], volume=volume)
        if res.status_code != 200:
            arrayv6.patch_volumes(
                names=[module.params["name"]],
                volume=flasharray.VolumePatch(destroyed=True),
            )
            arrayv6.delete_volumes(names=[module.params["name"]])
            module.fail_json(
                msg="Failed to set DMM Priority Adjustment on volume {0}. Error: {1}".format(
                    module.params["name"], res.errors[0].message
                )
            )
        else:
            volfact["priority_operator"] = module.params["priority_operator"]
            volfact["priority_value"] = module.params["priority_value"]
    if module.params["pgroup"] and DEFAULT_API_VERSION not in api_version:
        changed = True
        if not module.check_mode:
            try:
                array.set_pgroup(
                    module.params["pgroup"], addvollist=[module.params["name"]]
                )
            except Exception:
                module.warn_json(
                    "Failed to add {0} to protection group {1}.".format(
                        module.params["name"], module.params["pgroup"]
                    )
                )

    module.exit_json(changed=changed, volume=volfact)


def create_multi_volume(module, array, single=False):
    """Create Volume"""
    volfact = {}
    changed = True
    api_version = array._list_available_rest_versions()
    bw_qos_size = iops_qos_size = 0
    names = []
    if "/" in module.params["name"] and not check_vgroup(module, array):
        module.fail_json(
            msg="Multi-volume create failed. Volume Group {0} does not exist.".format(
                module.params["name"].split("/")[0]
            )
        )
    if "::" in module.params["name"]:
        if not check_pod(module, array):
            module.fail_json(
                msg="Multi-volume create failed. Pod {0} does not exist".format(
                    module.params["name"].split(":")[0]
                )
            )
        pod_name = module.params["name"].split("::")[0]
        if PROMOTE_API_VERSION in api_version:
            if array.get_pod(pod_name)["promotion_status"] == "demoted":
                module.fail_json(msg="Volume cannot be created in a demoted pod")
    array = get_array(module)
    if not single:
        for vol_num in range(
            module.params["start"], module.params["count"] + module.params["start"]
        ):
            names.append(
                module.params["name"]
                + str(vol_num).zfill(module.params["digits"])
                + module.params["suffix"]
            )
    else:
        names.append(module.params["name"])
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
        vols = flasharray.VolumePost(
            provisioned=human_to_bytes(module.params["size"]),
            qos=flasharray.Qos(bandwidth_limit=bw_qos_size, iops_limit=iops_qos_size),
            subtype="regular",
        )
    elif bw_qos_size == 0 and iops_qos_size == 0:
        vols = flasharray.VolumePost(
            provisioned=human_to_bytes(module.params["size"]), subtype="regular"
        )
    elif bw_qos_size == 0 and iops_qos_size != 0:
        vols = flasharray.VolumePost(
            provisioned=human_to_bytes(module.params["size"]),
            qos=flasharray.Qos(iops_limit=iops_qos_size),
            subtype="regular",
        )
    elif bw_qos_size != 0 and iops_qos_size == 0:
        vols = flasharray.VolumePost(
            provisioned=human_to_bytes(module.params["size"]),
            qos=flasharray.Qos(bandwidth_limit=bw_qos_size),
            subtype="regular",
        )
    if not module.check_mode:
        if DEFAULT_API_VERSION in api_version:
            if module.params["add_to_pgs"]:
                add_to_pgs = []
                for add_pg in range(0, len(module.params["add_to_pgs"])):
                    add_to_pgs.append(
                        flasharray.FixedReference(
                            name=module.params["add_to_pgs"][add_pg]
                        )
                    )
                res = array.post_volumes(
                    names=names,
                    volume=vols,
                    with_default_protection=module.params["with_default_protection"],
                    add_to_protection_groups=add_to_pgs,
                )
            else:
                res = array.post_volumes(
                    names=names,
                    volume=vols,
                    with_default_protection=module.params["with_default_protection"],
                )
        else:
            res = array.post_volumes(names=names, volume=vols)
        if res.status_code != 200:
            module.fail_json(
                msg="Multi-Volume {0}#{1} creation failed: {2}".format(
                    module.params["name"],
                    module.params["suffix"],
                    res.errors[0].message,
                )
            )
        else:
            if (
                VOLUME_PROMOTION_API_VERSION in api_version
                and module.params["promotion_state"]
            ):
                volume = flasharray.VolumePatch(
                    requested_promotion_state=module.params["promotion_state"]
                )
                prom_res = array.patch_volumes(names=names, volume=volume)
                if prom_res.status_code != 200:
                    array.patch_volumes(
                        names=names,
                        volume=flasharray.VolumePatch(destroyed=True),
                    )
                    array.delete_volumes(names=names)
                    module.warn(
                        "Failed to set promotion status on volumes. Error: {0}".format(
                            prom_res.errors[0].message
                        )
                    )
            if (
                PRIORITY_API_VERSION in api_version
                and module.params["priority_operator"]
            ):
                volume = flasharray.VolumePatch(
                    priority_adjustment=flasharray.PriorityAdjustment(
                        priority_adjustment_operator=module.params["priority_operator"],
                        priority_adjustment_value=module.params["priority_value"],
                    )
                )
                prio_res = array.patch_volumes(names=names, volume=volume)
                if prio_res.status_code != 200:
                    array.patch_volumes(
                        names=names,
                        volume=flasharray.VolumePatch(destroyed=True),
                    )
                    array.delete_volumes(names=names)
                    module.fail_json(
                        msg="Failed to set DMM Priority Adjustment on volumes. Error: {0}".format(
                            prio_res.errors[0].message
                        )
                    )
                prio_temp = list(prio_res.items)
            temp = list(res.items)
            for count in range(0, len(temp)):
                vol_name = temp[count].name
                volfact[vol_name] = {
                    "size": temp[count].provisioned,
                    "serial": temp[count].serial,
                    "created": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(temp[count].created / 1000)
                    ),
                    "page83_naa": PURE_OUI + temp[count].serial.lower(),
                    "nvme_nguid": _create_nguid(temp[count].serial.lower()),
                }
                if bw_qos_size != 0:
                    volfact[vol_name]["bandwidth_limit"] = temp[
                        count
                    ].qos.bandwidth_limit
                if iops_qos_size != 0:
                    volfact[vol_name]["iops_limit"] = temp[count].qos.iops_limit
                if (
                    VOLUME_PROMOTION_API_VERSION in api_version
                    and module.params["promotion_state"]
                ):
                    volfact[vol_name]["promotion_status"] = prio_temp[
                        count
                    ].promotion_status
                if (
                    PRIORITY_API_VERSION in api_version
                    and module.params["priority_operator"]
                ):
                    volfact[vol_name]["priority_operator"] = prio_temp[
                        count
                    ].priority_adjustment.priority_adjustment_operator
                    volfact[vol_name]["priority_value"] = prio_temp[
                        count
                    ].priority_adjustment.priority_adjustment_value

    if module.params["pgroup"] and DEFAULT_API_VERSION not in api_version:
        if not module.check_mode:
            res = array.post_protection_groups_volumes(
                group_names=[module.params["pgroup"]], member_names=names
            )
            if res.status_code != 200:
                module.warn(
                    "Failed to add {0} to protection group {1}.".format(
                        module.params["name"], module.params["pgroup"]
                    )
                )

    module.exit_json(changed=changed, volume=volfact)


def copy_from_volume(module, array):
    """Create Volume Clone"""
    volfact = []
    changed = False
    tgt = get_target(module, array)
    api_version = array._list_available_rest_versions()
    arrayv6 = get_array(module)
    if tgt is None:
        changed = True
        if not module.check_mode:
            if DEFAULT_API_VERSION in api_version:
                if module.params["add_to_pgs"]:
                    add_to_pgs = []
                    for add_pg in range(0, len(module.params["add_to_pgs"])):
                        add_to_pgs.append(
                            flasharray.FixedReference(
                                name=module.params["add_to_pgs"][add_pg]
                            )
                        )
                    res = arrayv6.post_volumes(
                        with_default_protection=module.params[
                            "with_default_protection"
                        ],
                        add_to_protection_groups=add_to_pgs,
                        names=[module.params["target"]],
                        volume=flasharray.VolumePost(
                            source=flasharray.Reference(name=module.params["name"])
                        ),
                    )
                else:
                    res = arrayv6.post_volumes(
                        with_default_protection=module.params[
                            "with_default_protection"
                        ],
                        names=[module.params["target"]],
                        volume=flasharray.VolumePost(
                            source=flasharray.Reference(name=module.params["name"])
                        ),
                    )

                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to copy volume {0} to {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["target"],
                            res.errors[0].message,
                        )
                    )
                vol_data = list(res.items)
                volfact = {
                    "size": vol_data[0].provisioned,
                    "serial": vol_data[0].serial,
                    "created": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(vol_data[0].created / 1000)
                    ),
                    "page83_naa": PURE_OUI + vol_data[0].serial.lower(),
                    "nvme_nguid": _create_nguid(vol_data[0].serial.lower()),
                }
            else:
                try:
                    volfact = array.copy_volume(
                        module.params["name"], module.params["target"]
                    )
                    volfact["page83_naa"] = PURE_OUI + volfact["serial"].lower()
                    volfact["nvme_nguid"] = _create_nguid(volfact["serial"].lower())
                    changed = True
                except Exception:
                    module.fail_json(
                        msg="Copy volume {0} to volume {1} failed.".format(
                            module.params["name"], module.params["target"]
                        )
                    )
    elif tgt is not None and module.params["overwrite"]:
        changed = True
        if not module.check_mode:
            if DEFAULT_API_VERSION not in api_version:
                try:
                    volfact = array.copy_volume(
                        module.params["name"],
                        module.params["target"],
                        overwrite=module.params["overwrite"],
                    )
                    volfact["page83_naa"] = PURE_OUI + volfact["serial"].lower()
                    volfact["nvme_nguid"] = _create_nguid(volfact["serial"].lower())
                    changed = True
                except Exception:
                    module.fail_json(
                        msg="Copy volume {0} to volume {1} failed.".format(
                            module.params["name"], module.params["target"]
                        )
                    )
            else:
                res = arrayv6.post_volumes(
                    overwrite=module.params["overwrite"],
                    names=[module.params["target"]],
                    volume=flasharray.VolumePost(
                        source=flasharray.Reference(name=module.params["name"])
                    ),
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to copy volume {0} to {1}. Error: {2}".format(
                            module.params["name"],
                            module.params["target"],
                            res.errors[0].message,
                        )
                    )
                vol_data = list(res.items)
                volfact = {
                    "size": vol_data[0].provisioned,
                    "serial": vol_data[0].serial,
                    "created": time.strftime(
                        "%Y-%m-%d %H:%M:%S", time.localtime(vol_data[0].created / 1000)
                    ),
                    "page83_naa": PURE_OUI + vol_data[0].serial.lower(),
                    "nvme_nguid": _create_nguid(vol_data[0].serial.lower()),
                }

    module.exit_json(changed=changed, volume=volfact)


def update_volume(module, array):
    """Update Volume size and/or QoS"""
    volfact = {}
    changed = False
    arrayv6 = None
    api_version = array._list_available_rest_versions()
    if MULTI_VOLUME_VERSION in api_version:
        arrayv6 = get_array(module)
    vol = array.get_volume(module.params["name"])
    vol_qos = array.get_volume(module.params["name"], qos=True)
    if QOS_API_VERSION in api_version:
        if vol_qos["bandwidth_limit"] is None:
            vol_qos["bandwidth_limit"] = 0
    if IOPS_API_VERSION in api_version:
        if vol_qos["iops_limit"] is None:
            vol_qos["iops_limit"] = 0
    if "::" in module.params["name"]:
        if module.params["bw_qos"] or module.params["iops_qos"]:
            if AC_QOS_VERSION not in api_version:
                module.warn(
                    "Pods cannot cannot contain volumes with QoS settings. Ignoring..."
                )
                module.params["bw_qos"] = module.params["iops_qos"] = None
    if module.params["size"]:
        if human_to_bytes(module.params["size"]) != vol["size"]:
            if human_to_bytes(module.params["size"]) > vol["size"]:
                changed = True
                if not module.check_mode:
                    try:
                        volfact = array.extend_volume(
                            module.params["name"], module.params["size"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Volume {0} resize failed.".format(
                                module.params["name"]
                            )
                        )
    if module.params["bw_qos"] and QOS_API_VERSION in api_version:
        if int(human_to_bytes(module.params["bw_qos"])) != int(
            vol_qos["bandwidth_limit"]
        ):
            if module.params["bw_qos"] == "0":
                changed = True
                if not module.check_mode:
                    try:
                        volfact = array.set_volume(
                            module.params["name"], bandwidth_limit=""
                        )
                    except Exception:
                        module.fail_json(
                            msg="Volume {0} Bandwidth QoS removal failed.".format(
                                module.params["name"]
                            )
                        )
            elif int(human_to_bytes(module.params["bw_qos"])) in range(
                1048576, 549755813888
            ):
                changed = True
                if not module.check_mode:
                    try:
                        volfact = array.set_volume(
                            module.params["name"],
                            bandwidth_limit=module.params["bw_qos"],
                        )
                    except Exception:
                        module.fail_json(
                            msg="Volume {0} Bandwidth QoS change failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(
                    msg="Bandwidth QoS value {0} out of range.".format(
                        module.params["bw_qos"]
                    )
                )
    if module.params["iops_qos"] and IOPS_API_VERSION in api_version:
        if int(human_to_real(module.params["iops_qos"])) != int(vol_qos["iops_limit"]):
            if module.params["iops_qos"] == "0":
                changed = True
                if not module.check_mode:
                    try:
                        volfact = array.set_volume(module.params["name"], iops_limit="")
                    except Exception:
                        module.fail_json(
                            msg="Volume {0} IOPs QoS removal failed.".format(
                                module.params["name"]
                            )
                        )
            elif int(human_to_real(module.params["iops_qos"])) in range(100, 100000000):
                changed = True
                if not module.check_mode:
                    try:
                        volfact = array.set_volume(
                            module.params["name"], iops_limit=module.params["iops_qos"]
                        )
                    except Exception:
                        module.fail_json(
                            msg="Volume {0} IOPs QoS change failed.".format(
                                module.params["name"]
                            )
                        )
            else:
                module.fail_json(
                    msg="Bandwidth QoS value {0} out of range.".format(
                        module.params["bw_qos"]
                    )
                )
    if VOLUME_PROMOTION_API_VERSION in api_version and module.params["promotion_state"]:
        vol6 = list(arrayv6.get_volumes(names=[module.params["name"]]).items)[0]
        if module.params["promotion_state"] != vol6.promotion_status:
            volume_patch = flasharray.VolumePatch(
                requested_promotion_state=module.params["promotion_state"]
            )
            changed = True
            if not module.check_mode:
                prom_res = arrayv6.patch_volumes(
                    names=[module.params["name"]], volume=volume_patch
                )
                if prom_res.status_code != 200:
                    module.fail_json(
                        msg="Failed to change promotion status for volume {0}.".format(
                            module.params["name"]
                        )
                    )
                else:
                    if not volfact:
                        volfact = array.get_volume(module.params["name"])
                        volfact["promotion_status"] = module.params["promotion_state"]
    if PRIORITY_API_VERSION in api_version and module.params["priority_operator"]:
        volv6 = list(arrayv6.get_volumes(names=[module.params["name"]]).items)[0]
        change_prio = False
        if (
            module.params["priority_operator"]
            != volv6.priority_adjustment.priority_adjustment_operator
        ):
            change_prio = True
            newop = module.params["priority_operator"]
        else:
            newop = volv6.priority_adjustment.priority_adjustment_operator
        if (
            module.params["priority_value"]
            and module.params["priority_value"]
            != volv6.priority_adjustment.priority_adjustment_value
        ):
            change_prio = True
            newval = module.params["priority_value"]
        elif (
            not module.params["priority_value"]
            and volv6.priority_adjustment.priority_adjustment_value != 0
        ):
            change_prio = True
            newval = 0
        else:
            newval = volv6.priority_adjustment.priority_adjustment_value
        volumepatch = flasharray.VolumePatch(
            priority_adjustment=flasharray.PriorityAdjustment(
                priority_adjustment_operator=newop,
                priority_adjustment_value=newval,
            )
        )
        if change_prio and not module.check_mode:
            changed = True
            prio_res = arrayv6.patch_volumes(
                names=[module.params["name"]], volume=volumepatch
            )
            if prio_res.status_code != 200:
                module.fail_json(
                    msg="Failed to change DMM Priority Adjustment for {0}. Error: {1}".format(
                        module.params["name"], prio_res.errors[0].message
                    )
                )
            else:
                if not volfact:
                    volfact = array.get_volume(module.params["name"])
                volfact["priority_operator"] = module.params["priority_operator"]
                volfact["priority_value"] = module.params["priority_value"]
    if MULTI_VOLUME_VERSION in api_version:
        volume_data = list(arrayv6.get_volumes(names=[module.params["name"]]).items)[0]
        updatefacts = {
            "name": volume_data.name,
            "size": volume_data.provisioned,
            "serial": volume_data.serial,
            "created": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(volume_data.created / 1000)
            ),
            "page83_naa": PURE_OUI + volume_data.serial.lower(),
            "nvme_nguid": _create_nguid(volume_data.serial.lower()),
        }
    else:
        updatefacts = array.get_volume(module.params["name"])
    vol_fact = {**volfact, **updatefacts}
    module.exit_json(changed=changed, volume=vol_fact)


def rename_volume(module, array):
    """Rename volume within a container, ie pod, vgroup or local array"""
    volfact = []
    changed = False
    pod_name = ""
    vgroup_name = ""
    target_name = module.params["rename"]
    target_exists = False
    if "::" in module.params["name"]:
        pod_name = module.params["name"].split("::")[0]
        target_name = pod_name + "::" + module.params["rename"]
        try:
            array.get_volume(target_name, pending=True)
            target_exists = True
        except Exception:
            target_exists = False
    elif "/" in module.params["name"]:
        vgroup_name = module.params["name"].split("/")[0]
        target_name = vgroup_name + "/" + module.params["rename"]
        try:
            array.get_volume(target_name, pending=True)
            target_exists = True
        except Exception:
            target_exists = False
    else:
        try:
            array.get_volume(target_name, pending=True)
            target_exists = True
        except Exception:
            target_exists = False
    if target_exists and get_endpoint(target_name, array):
        module.fail_json(
            msg="Target volume {0} is a protocol-endpoinnt".format(target_name)
        )
    if not target_exists:
        if get_destroyed_endpoint(target_name, array):
            module.fail_json(
                msg="Target volume {0} is a destroyed protocol-endpoinnt".format(
                    target_name
                )
            )
        else:
            changed = True
            if not module.check_mode:
                try:
                    volfact = array.rename_volume(
                        module.params["name"], module.params["rename"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Rename volume {0} to {1} failed.".format(
                            module.params["name"], module.params["rename"]
                        )
                    )
    else:
        module.fail_json(msg="Target volume {0} already exists.".format(target_name))

    module.exit_json(changed=changed, volume=volfact)


def move_volume(module, array):
    """Move volume between pods, vgroups or local array"""
    volfact = []
    changed = vgroup_exists = target_exists = pod_exists = False
    api_version = array._list_available_rest_versions()
    pod_name = ""
    vgroup_name = ""
    volume_name = module.params["name"]
    if "::" in module.params["name"]:
        volume_name = module.params["name"].split("::")[1]
        pod_name = module.params["name"].split("::")[0]
    if "/" in module.params["name"]:
        volume_name = module.params["name"].split("/")[1]
        vgroup_name = module.params["name"].split("/")[0]
    if module.params["move"] == "local":
        target_location = ""
        if "::" not in module.params["name"]:
            if "/" not in module.params["name"]:
                module.fail_json(
                    msg="Source and destination [local] cannot be the same."
                )
        try:
            target_exists = array.get_volume(volume_name, pending=True)
        except Exception:
            target_exists = False
        if target_exists:
            module.fail_json(msg="Target volume {0} already exists".format(volume_name))
    else:
        try:
            pod_exists = array.get_pod(module.params["move"])
            if len(pod_exists["arrays"]) > 1:
                module.fail_json(msg="Volume cannot be moved into a stretched pod")
            if pod_exists["link_target_count"] != 0:
                module.fail_json(msg="Volume cannot be moved into a linked source pod")
            if PROMOTE_API_VERSION in api_version:
                if pod_exists["promotion_status"] == "demoted":
                    module.fail_json(msg="Volume cannot be moved into a demoted pod")
            pod_exists = bool(pod_exists)
        except Exception:
            pod_exists = False
        if pod_exists:
            try:
                target_exists = bool(
                    array.get_volume(
                        module.params["move"] + "::" + volume_name, pending=True
                    )
                )
            except Exception:
                target_exists = False
        try:
            vgroup_exists = bool(array.get_vgroup(module.params["move"]))
        except Exception:
            vgroup_exists = False
        if vgroup_exists:
            try:
                target_exists = bool(
                    array.get_volume(
                        module.params["move"] + "/" + volume_name, pending=True
                    )
                )
            except Exception:
                target_exists = False
        if target_exists:
            module.fail_json(msg="Volume of same name already exists in move location")
        if pod_exists and vgroup_exists:
            module.fail_json(
                msg="Move location {0} matches both a pod and a vgroup. Please rename one of these.".format(
                    module.params["move"]
                )
            )
        if not pod_exists and not vgroup_exists:
            module.fail_json(
                msg="Move location {0} does not exist.".format(module.params["move"])
            )
        if "::" in module.params["name"]:
            pod = array.get_pod(module.params["move"])
            if len(pod["arrays"]) > 1:
                module.fail_json(msg="Volume cannot be moved out of a stretched pod")
            if pod["linked_target_count"] != 0:
                module.fail_json(
                    msg="Volume cannot be moved out of a linked source pod"
                )
            if PROMOTE_API_VERSION in api_version:
                if pod["promotion_status"] == "demoted":
                    module.fail_json(msg="Volume cannot be moved out of a demoted pod")
        if "/" in module.params["name"]:
            if (
                vgroup_name == module.params["move"]
                or pod_name == module.params["move"]
            ):
                module.fail_json(msg="Source and destination cannot be the same")
        target_location = module.params["move"]
    if get_endpoint(target_location, array):
        module.fail_json(
            msg="Target volume {0} is a protocol-endpoinnt".format(target_location)
        )
    changed = True
    if not module.check_mode:
        try:
            volfact = array.move_volume(module.params["name"], target_location)
        except Exception:
            if target_location == "":
                target_location = "[local]"
            module.fail_json(
                msg="Move of volume {0} to {1} failed.".format(
                    module.params["name"], target_location
                )
            )
    module.exit_json(changed=changed, volume=volfact)


def delete_volume(module, array):
    """Delete Volume"""
    changed = True
    volfact = []
    if not module.check_mode:
        try:
            array.destroy_volume(module.params["name"])
            if module.params["eradicate"]:
                try:
                    volfact = array.eradicate_volume(module.params["name"])
                except Exception:
                    module.fail_json(
                        msg="Eradicate volume {0} failed.".format(module.params["name"])
                    )
        except Exception:
            module.fail_json(
                msg="Delete volume {0} failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed, volume=volfact)


def eradicate_volume(module, array):
    """Eradicate Deleted Volume"""
    changed = True
    volfact = []
    if not module.check_mode:
        if module.params["eradicate"]:
            try:
                array.eradicate_volume(module.params["name"])
            except Exception:
                module.fail_json(
                    msg="Eradication of volume {0} failed".format(module.params["name"])
                )
    module.exit_json(changed=changed, volume=volfact)


def recover_volume(module, array):
    """Recover Deleted Volume"""
    changed = True
    volfact = []
    if not module.check_mode:
        try:
            array.recover_volume(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Recovery of volume {0} failed".format(module.params["name"])
            )
        volfact = array.get_volume(module.params["name"])
        volfact["page83_naa"] = PURE_OUI + volfact["serial"].lower()
        volfact["nvme_nguid"] = _create_nguid(volfact["serial"].lower())
    module.exit_json(changed=changed, volume=volfact)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            target=dict(type="str"),
            move=dict(type="str"),
            rename=dict(type="str"),
            overwrite=dict(type="bool", default=False),
            eradicate=dict(type="bool", default=False),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            bw_qos=dict(type="str", aliases=["qos"]),
            iops_qos=dict(type="str"),
            pgroup=dict(type="str"),
            count=dict(type="int"),
            start=dict(type="int", default=0),
            digits=dict(type="int", default=1),
            suffix=dict(type="str"),
            priority_operator=dict(type="str", choices=["+", "-", "="]),
            priority_value=dict(type="int", choices=[-10, 0, 10]),
            size=dict(type="str"),
            with_default_protection=dict(type="bool", default=True),
            add_to_pgs=dict(type="list", elements="str"),
            promotion_state=dict(type="str", choices=["promoted", "demoted"]),
        )
    )

    mutually_exclusive = [
        ["size", "target"],
        ["move", "rename", "target", "eradicate"],
        ["rename", "move", "target", "eradicate"],
    ]
    required_together = [["priority_operator", "priority_value"]]

    module = AnsibleModule(
        argument_spec,
        mutually_exclusive=mutually_exclusive,
        required_together=required_together,
        supports_check_mode=True,
    )

    size = module.params["size"]
    bw_qos = module.params["bw_qos"]
    iops_qos = module.params["iops_qos"]
    state = module.params["state"]
    destroyed = False
    array = get_system(module)
    volume = get_volume(module, array)
    api_version = array._list_available_rest_versions()
    endpoint = get_endpoint(module.params["name"], array)

    if endpoint:
        module.fail_json(
            msg="Volume {0} is an endpoint. Use purefa_endpoint module.".format(
                module.params["name"]
            )
        )

    if module.params["pgroup"]:
        pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
        if ":" in module.params["pgroup"] and OFFLOAD_API_VERSION not in api_version:
            module.fail_json(
                msg="API version does not support offload protection groups."
            )
        if "::" in module.params["pgroup"] and POD_API_VERSION not in api_version:
            module.fail_json(
                msg="API version does not support ActiveCluster protection groups."
            )
        if ":" in module.params["pgroup"]:
            if "::" in module.params["pgroup"]:
                pgname = module.params["pgroup"].split("::")[1]
            else:
                pgname = module.params["pgroup"].split(":")[1]
            if not pattern.match(pgname):
                module.fail_json(
                    msg="Protection Group name {0} does not conform to naming convention".format(
                        pgname
                    )
                )
        else:
            if not pattern.match(module.params["pgroup"]):
                module.fail_json(
                    msg="Protection Group name {0} does not conform to naming convention".format(
                        pgname
                    )
                )
        pgroup = get_pgroup(module, array)
        xpgroup = get_pending_pgroup(module, array)
        if "::" in module.params["pgroup"]:
            if not get_pod(module, array):
                module.fail_json(
                    msg="Pod {0} does not exist.".format(
                        module.params["pgroup"].split("::")[0]
                    )
                )
        if not pgroup:
            if xpgroup:
                module.fail_json(
                    msg="Protection Group {0} is currently deleted. Please restore to use.".format(
                        module.params["pgroup"]
                    )
                )
            else:
                module.fail_json(
                    msg="Protection Group {0} does not exist.".format(
                        module.params["pgroup"]
                    )
                )

    if not volume:
        destroyed = get_destroyed_volume(module.params["name"], array)
    target = get_target(module, array)
    if module.params["count"]:
        if not HAS_PURESTORAGE:
            module.fail_json(
                msg="py-pure-client sdk is required to support 'count' parameter"
            )
        if MULTI_VOLUME_VERSION not in api_version:
            module.fail_json(
                msg="'count' parameter is not supported until Purity//FA 6.0.0 or higher"
            )
        if module.params["digits"] and module.params["digits"] not in range(1, 10):
            module.fail_json(msg="'digits' must be in the range of 1 to 10")
        if module.params["start"] < 0:
            module.fail_json(msg="'start' must be a positive number")
        volume = get_multi_volumes(module)
        if state == "present" and not volume and size:
            create_multi_volume(module, array)
        elif state == "present" and not volume and not size:
            module.fail_json(msg="Size must be specified to create a new volume")
        elif state == "absent" and not volume:
            module.exit_json(changed=False)
        else:
            module.warn("Method not yet supported for multi-volume")
    else:
        if state == "present" and not volume and not destroyed and size:
            if DEFAULT_API_VERSION in api_version:
                create_multi_volume(module, array, True)
            else:
                create_volume(module, array)
        elif (
            state == "present"
            and volume
            and (size or bw_qos or iops_qos or module.params["promotion_state"])
        ):
            update_volume(module, array)
        elif state == "present" and not volume and module.params["move"]:
            module.fail_json(
                msg="Volume {0} cannot be moved - does not exist (maybe deleted)".format(
                    module.params["name"]
                )
            )
        elif state == "present" and volume and module.params["move"]:
            move_volume(module, array)
        elif state == "present" and volume and module.params["rename"]:
            rename_volume(module, array)
        elif (
            state == "present"
            and destroyed
            and not module.params["move"]
            and not module.params["rename"]
        ):
            recover_volume(module, array)
        elif state == "present" and destroyed and module.params["move"]:
            module.fail_json(
                msg="Volume {0} exists, but in destroyed state".format(
                    module.params["name"]
                )
            )
        elif state == "present" and volume and target:
            copy_from_volume(module, array)
        elif state == "present" and volume and not target:
            copy_from_volume(module, array)
        elif state == "absent" and volume:
            delete_volume(module, array)
        elif state == "absent" and destroyed:
            eradicate_volume(module, array)
        elif state == "present":
            if not volume and not size:
                module.fail_json(msg="Size must be specified to create a new volume")
        elif state == "absent" and not volume:
            module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
