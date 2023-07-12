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
module: purefa_host
version_added: '1.0.0'
short_description: Manage hosts on Pure Storage FlashArrays
description:
- Create, delete or modify hosts on Pure Storage FlashArrays.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- If specifying C(lun) option ensure host support requested value
options:
  name:
    description:
    - The name of the host.
    - Note that hostnames are case-sensitive however FlashArray hostnames are unique
      and ignore case - you cannot have I(hosta) and I(hostA)
    - Multi-host support available from Purity//FA 6.0.0
      B(***NOTE***) Manual deletion of individual hosts created
      using multi-host will cause idempotency to fail
    - Multi-host support only exists for host creation
    type: str
    required: true
    aliases: [ host ]
  protocol:
    description:
    - Defines the host connection protocol for volumes.
    - DEPRECATED No longer a necessary parameter
    type: str
    choices: [ fc, iscsi, nvme, mixed ]
  rename:
    description:
    - The name to rename to.
    - Note that hostnames are case-sensitive however FlashArray hostnames are unique
      and ignore case - you cannot have I(hosta) and I(hostA)
    type: str
  state:
    description:
    - Define whether the host should exist or not.
    - When removing host all connected volumes will be disconnected.
    type: str
    default: present
    choices: [ absent, present ]
  wwns:
    type: list
    elements: str
    description:
    - List of wwns of the host.
  iqn:
    type: list
    elements: str
    description:
    - List of IQNs of the host.
  nqn:
    type: list
    elements: str
    description:
    - List of NQNs of the host.
  volume:
    type: str
    description:
    - Volume name to map to the host.
  lun:
    description:
    - LUN ID to assign to volume for host. Must be unique.
    - If not provided the ID will be automatically assigned.
    - Range for LUN ID is 1 to 4095.
    type: int
  count:
    description:
    - Number of hosts to be created in a multiple host creation
    - Only supported from Purity//FA v6.0.0 and higher
    type: int
  start:
    description:
    - Number at which to start the multiple host creation index
    - Only supported from Purity//FA v6.0.0 and higher
    type: int
    default: 0
  digits:
    description:
    - Number of digits to use for multiple host count. This
      will pad the index number with zeros where necessary
    - Only supported from Purity//FA v6.0.0 and higher
    - Range is between 1 and 10
    type: int
    default: 1
  suffix:
    description:
    - Suffix string, if required, for multiple host create
    - Host names will be formed as I(<name>#<suffix>), where
      I(#) is a placeholder for the host index
      See associated descriptions
    - Suffix string is optional
    - Only supported from Purity//FA v6.0.0 and higher
    type: str
  personality:
    type: str
    description:
    - Define which operating system the host is. Recommended for
      ActiveCluster integration.
    default: ''
    choices: ['hpux', 'vms', 'aix', 'esxi', 'solaris', 'hitachi-vsp', 'oracle-vm-server', 'delete', '']
  preferred_array:
    type: list
    elements: str
    description:
    - List of preferred arrays in an ActiveCluster environment.
    - To remove existing preferred arrays from the host, specify I(delete).
  target_user:
    type: str
    description:
    - Sets the target user name for CHAP authentication
    - Required with I(target_password)
    - To clear the username/password pair use I(clear) as the password
  target_password:
    type: str
    description:
    - Sets the target password for CHAP authentication
    - Password length between 12 and 255 characters
    - To clear the username/password pair use I(clear) as the password
    - SETTING A PASSWORD IS NON-IDEMPOTENT
  host_user:
    type: str
    description:
    - Sets the host user name for CHAP authentication
    - Required with I(host_password)
    - To clear the username/password pair use I(clear) as the password
  host_password:
    type: str
    description:
    - Sets the host password for CHAP authentication
    - Password length between 12 and 255 characters
    - To clear the username/password pair use I(clear) as the password
    - SETTING A PASSWORD IS NON-IDEMPOTENT
  vlan:
    type: str
    description:
    - The VLAN ID that the host is associated with.
    - If not set or set to I(any), the host can access any VLAN.
    - If set to I(untagged), the host can only access untagged VLANs.
    - If set to a number between 1 and 4094, the host can only access the specified VLAN with that number.
    version_added: '1.16.0'
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Create new AIX host
  purestorage.flasharray.purefa_host:
    name: foo
    personality: aix
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create 10 hosts with index starting at 10 but padded with 3 digits
  purestorage.flasharray.purefa_host:
    name: foo
    personality: vms
    suffix: bar
    count: 10
    start: 10
    digits: 3
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: present

- name: Rename host foo to bar
  purestorage.flasharray.purefa_host:
    name: foo
    rename: bar
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete host
  purestorage.flasharray.purefa_host:
    name: foo
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
    state: absent

- name: Make host bar with wwn ports
  purestorage.flasharray.purefa_host:
    name: bar
    wwns:
    - 00:00:00:00:00:00:00
    - 11:11:11:11:11:11:11
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Make host bar with iSCSI ports
  purestorage.flasharray.purefa_host:
    name: bar
    iqn:
    - iqn.1994-05.com.redhat:7d366003913
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Make host bar with NVMe ports
  purestorage.flasharray.purefa_host:
    name: bar
    nqn:
    - nqn.2014-08.com.vendor:nvme:nvm-subsystem-sn-d78432
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Make mixed protocol host
  purestorage.flasharray.purefa_host:
    name: bar
    nqn:
    - nqn.2014-08.com.vendor:nvme:nvm-subsystem-sn-d78432
    iqn:
    - iqn.1994-05.com.redhat:7d366003914
    wwns:
    - 00:00:00:00:00:00:01
    - 11:11:11:11:11:11:12
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Map host foo to volume bar as LUN ID 12
  purestorage.flasharray.purefa_host:
    name: foo
    volume: bar
    lun: 12
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disconnect volume bar from host foo
  purestorage.flasharray.purefa_host:
    name: foo
    volume: bar
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Add preferred arrays to host foo
  purestorage.flasharray.purefa_host:
    name: foo
    preferred_array:
    - array1
    - array2
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete preferred arrays from host foo
  purestorage.flasharray.purefa_host:
    name: foo
    preferred_array: delete
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete exisitng WWNs from host foo (does not delete host object)
  purestorage.flasharray.purefa_host:
    name: foo
    wwns: ""
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Set CHAP target and host username/password pairs
  purestorage.flasharray.purefa_host:
    name: foo
    target_user: user1
    target_password: passwrodpassword
    host_user: user2
    host_password: passwrodpassword
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete CHAP target and host username/password pairs
  purestorage.flasharray.purefa_host:
    name: foo
    target_user: user
    target_password: clear
    host_user: user
    host_password: clear
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

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


AC_REQUIRED_API_VERSION = "1.14"
PREFERRED_ARRAY_API_VERSION = "1.15"
NVME_API_VERSION = "1.16"
MULTI_HOST_VERSION = "2.2"
VLAN_VERSION = "2.16"


def _is_cbs(array, is_cbs=False):
    """Is the selected array a Cloud Block Store"""
    model = array.get(controllers=True)[0]["model"]
    is_cbs = bool("CBS" in model)
    return is_cbs


def _set_host_initiators(module, array):
    """Set host initiators."""
    if module.params["nqn"]:
        try:
            array.set_host(module.params["name"], nqnlist=module.params["nqn"])
        except Exception:
            module.fail_json(msg="Setting of NVMe NQN failed.")
    if module.params["iqn"]:
        try:
            array.set_host(module.params["name"], iqnlist=module.params["iqn"])
        except Exception:
            module.fail_json(msg="Setting of iSCSI IQN failed.")
    if module.params["wwns"]:
        try:
            array.set_host(module.params["name"], wwnlist=module.params["wwns"])
        except Exception:
            module.fail_json(msg="Setting of FC WWNs failed.")


def _update_host_initiators(module, array, answer=False):
    """Change host initiator if iscsi or nvme or add new FC WWNs"""
    if module.params["nqn"]:
        current_nqn = array.get_host(module.params["name"])["nqn"]
        if module.params["nqn"] != [""]:
            if current_nqn != module.params["nqn"]:
                answer = True
                if not module.check_mode:
                    try:
                        array.set_host(
                            module.params["name"], nqnlist=module.params["nqn"]
                        )
                    except Exception:
                        module.fail_json(msg="Change of NVMe NQN failed.")
        elif current_nqn:
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(module.params["name"], remnqnlist=current_nqn)
                except Exception:
                    module.fail_json(msg="Removal of NVMe NQN failed.")
    if module.params["iqn"]:
        current_iqn = array.get_host(module.params["name"])["iqn"]
        if module.params["iqn"] != [""]:
            if current_iqn != module.params["iqn"]:
                answer = True
                if not module.check_mode:
                    try:
                        array.set_host(
                            module.params["name"], iqnlist=module.params["iqn"]
                        )
                    except Exception:
                        module.fail_json(msg="Change of iSCSI IQN failed.")
        elif current_iqn:
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(module.params["name"], remiqnlist=current_iqn)
                except Exception:
                    module.fail_json(msg="Removal of iSCSI IQN failed.")
    if module.params["wwns"]:
        module.params["wwns"] = [wwn.replace(":", "") for wwn in module.params["wwns"]]
        module.params["wwns"] = [wwn.upper() for wwn in module.params["wwns"]]
        current_wwn = array.get_host(module.params["name"])["wwn"]
        if module.params["wwns"] != [""]:
            if current_wwn != module.params["wwns"]:
                answer = True
                if not module.check_mode:
                    try:
                        array.set_host(
                            module.params["name"], wwnlist=module.params["wwns"]
                        )
                    except Exception:
                        module.fail_json(msg="FC WWN change failed.")
        elif current_wwn:
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(module.params["name"], remwwnlist=current_wwn)
                except Exception:
                    module.fail_json(msg="Removal of all FC WWNs failed.")
    return answer


def _connect_new_volume(module, array, answer=False):
    """Connect volume to host"""
    api_version = array._list_available_rest_versions()
    if AC_REQUIRED_API_VERSION in api_version and module.params["lun"]:
        answer = True
        if not module.check_mode:
            try:
                array.connect_host(
                    module.params["name"],
                    module.params["volume"],
                    lun=module.params["lun"],
                )
            except Exception:
                module.fail_json(
                    msg="LUN ID {0} invalid. Check for duplicate LUN IDs.".format(
                        module.params["lun"]
                    )
                )
    else:
        answer = True
        if not module.check_mode:
            array.connect_host(module.params["name"], module.params["volume"])
    return answer


def _disconnect_volume(module, array, answer=False):
    """Disconnect volume from host"""
    answer = True
    if not module.check_mode:
        try:
            array.disconnect_host(module.params["name"], module.params["volume"])
        except Exception:
            module.fail_json(
                msg="Failed to disconnect volume {0}".format(module.params["volume"])
            )
    return answer


def _set_host_personality(module, array):
    """Set host personality. Only called when supported"""
    if module.params["personality"] != "delete":
        array.set_host(module.params["name"], personality=module.params["personality"])
    else:
        array.set_host(module.params["name"], personality="")


def _set_preferred_array(module, array):
    """Set preferred array list. Only called when supported"""
    if module.params["preferred_array"] != ["delete"]:
        array.set_host(
            module.params["name"], preferred_array=module.params["preferred_array"]
        )
    else:
        array.set_host(module.params["name"], preferred_array=[])


def _set_chap_security(module, array):
    """Set CHAP usernames and passwords"""
    pattern = re.compile("[^ ]{12,255}")
    if module.params["host_user"]:
        if not pattern.match(module.params["host_password"]):
            module.fail_json(
                msg="host_password must contain a minimum of 12 and a maximum of 255 characters"
            )
        try:
            array.set_host(
                module.params["name"],
                host_user=module.params["host_user"],
                host_password=module.params["host_password"],
            )
        except Exception:
            module.params(msg="Failed to set CHAP host username and password")
    if module.params["target_user"]:
        if not pattern.match(module.params["target_password"]):
            module.fail_json(
                msg="target_password must contain a minimum of 12 and a maximum of 255 characters"
            )
        try:
            array.set_host(
                module.params["name"],
                target_user=module.params["target_user"],
                target_password=module.params["target_password"],
            )
        except Exception:
            module.params(msg="Failed to set CHAP target username and password")


def _update_chap_security(module, array, answer=False):
    """Change CHAP usernames and passwords"""
    pattern = re.compile("[^ ]{12,255}")
    chap = array.get_host(module.params["name"], chap=True)
    if module.params["host_user"]:
        if module.params["host_password"] == "clear":
            if chap["host_user"]:
                answer = True
                if not module.check_mode:
                    try:
                        array.set_host(module.params["name"], host_user="")
                    except Exception:
                        module.params(
                            msg="Failed to clear CHAP host username and password"
                        )
        else:
            if not pattern.match(module.params["host_password"]):
                module.fail_json(
                    msg="host_password must contain a minimum of 12 and a maximum of 255 characters"
                )
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(
                        module.params["name"],
                        host_user=module.params["host_user"],
                        host_password=module.params["host_password"],
                    )
                except Exception:
                    module.params(msg="Failed to set CHAP host username and password")
    if module.params["target_user"]:
        if module.params["target_password"] == "clear":
            if chap["target_user"]:
                answer = True
                if not module.check_mode:
                    try:
                        array.set_host(module.params["name"], target_user="")
                    except Exception:
                        module.params(
                            msg="Failed to clear CHAP target username and password"
                        )
        else:
            if not pattern.match(module.params["target_password"]):
                module.fail_json(
                    msg="target_password must contain a minimum of 12 and a maximum of 255 characters"
                )
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(
                        module.params["name"],
                        target_user=module.params["target_user"],
                        target_password=module.params["target_password"],
                    )
                except Exception:
                    module.params(msg="Failed to set CHAP target username and password")
    return answer


def _update_host_personality(module, array, answer=False):
    """Change host personality. Only called when supported"""
    personality = array.get_host(module.params["name"], personality=True)["personality"]
    if personality is None and module.params["personality"] != "delete":
        answer = True
        if not module.check_mode:
            try:
                array.set_host(
                    module.params["name"], personality=module.params["personality"]
                )
            except Exception:
                module.fail_json(msg="Personality setting failed.")
    if personality is not None:
        if module.params["personality"] == "delete":
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(module.params["name"], personality="")
                except Exception:
                    module.fail_json(msg="Personality deletion failed.")
        elif personality != module.params["personality"]:
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(
                        module.params["name"], personality=module.params["personality"]
                    )
                except Exception:
                    module.fail_json(msg="Personality change failed.")
    return answer


def _update_preferred_array(module, array, answer=False):
    """Update existing preferred array list. Only called when supported"""
    preferred_array = array.get_host(module.params["name"], preferred_array=True)[
        "preferred_array"
    ]
    if preferred_array == [] and module.params["preferred_array"] != ["delete"]:
        answer = True
        if not module.check_mode:
            try:
                array.set_host(
                    module.params["name"],
                    preferred_array=module.params["preferred_array"],
                )
            except Exception:
                module.fail_json(
                    msg="Preferred array list creation failed for {0}.".format(
                        module.params["name"]
                    )
                )
    elif preferred_array != []:
        if module.params["preferred_array"] == ["delete"]:
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(module.params["name"], preferred_array=[])
                except Exception:
                    module.fail_json(
                        msg="Preferred array list deletion failed for {0}.".format(
                            module.params["name"]
                        )
                    )
        elif preferred_array != module.params["preferred_array"]:
            answer = True
            if not module.check_mode:
                try:
                    array.set_host(
                        module.params["name"],
                        preferred_array=module.params["preferred_array"],
                    )
                except Exception:
                    module.fail_json(
                        msg="Preferred array list change failed for {0}.".format(
                            module.params["name"]
                        )
                    )
    return answer


def _set_vlan(module):
    array = get_array(module)
    res = array.patch_hosts(
        names=[module.params["name"]],
        host=flasharray.HostPatch(vlan=module.params["vlan"]),
    )
    if res.status_code != 200:
        module.warn(
            "Failed to set host VLAN ID. Error: {0}".format(res.errors[0].message)
        )


def _update_vlan(module):
    changed = False
    array = get_array(module)
    host_vlan = getattr(
        list(array.get_hosts(names=[module.params["name"]]).items)[0], "vlan", None
    )
    if module.params["vlan"] != host_vlan:
        changed = True
        if not module.check_mode:
            res = array.patch_hosts(
                names=[module.params["name"]],
                host=flasharray.HostPatch(vlan=module.params["vlan"]),
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update host VLAN ID. Error: {0}".format(
                        res.errors[0].message
                    )
                )
    return changed


def get_multi_hosts(module):
    """Return True is all hosts exist"""
    hosts = []
    array = get_array(module)
    for host_num in range(
        module.params["start"], module.params["count"] + module.params["start"]
    ):
        if module.params["suffix"]:
            hosts.append(
                module.params["name"]
                + str(host_num).zfill(module.params["digits"])
                + module.params["suffix"]
            )
        else:
            hosts.append(
                module.params["name"] + str(host_num).zfill(module.params["digits"])
            )
    return bool(array.get_hosts(names=hosts).status_code == 200)


def get_host(module, array):
    """Return host or None"""
    host = None
    for hst in array.list_hosts():
        if hst["name"].casefold() == module.params["name"].casefold():
            module.params["name"] = hst["name"]
            host = hst
            break
    return host


def rename_exists(module, array):
    """Determine if rename target already exists"""
    exists = False
    for hst in array.list_hosts():
        if hst["name"].casefold() == module.params["rename"].casefold():
            exists = True
            break
    return exists


def make_multi_hosts(module):
    """Create multiple hosts"""
    changed = True
    if not module.check_mode:
        hosts = []
        array = get_array(module)
        for host_num in range(
            module.params["start"], module.params["count"] + module.params["start"]
        ):
            if module.params["suffix"]:
                hosts.append(
                    module.params["name"]
                    + str(host_num).zfill(module.params["digits"])
                    + module.params["suffix"]
                )
            else:
                hosts.append(
                    module.params["name"] + str(host_num).zfill(module.params["digits"])
                )
        if module.params["personality"]:
            host = flasharray.HostPost(personality=module.params["personality"])
        else:
            host = flasharray.HostPost()
        res = array.post_hosts(names=hosts, host=host)
        if res.status_code != 200:
            module.fail_json(
                msg="Multi-Host {0}#{1} creation failed: {2}".format(
                    module.params["name"],
                    module.params["suffix"],
                    res.errors[0].message,
                )
            )
    module.exit_json(changed=changed)


def make_host(module, array):
    """Create a new host"""
    changed = True
    if not module.check_mode:
        try:
            array.create_host(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Host {0} creation failed.".format(module.params["name"])
            )
        try:
            if module.params["vlan"]:
                _set_vlan(module)
            _set_host_initiators(module, array)
            api_version = array._list_available_rest_versions()
            if AC_REQUIRED_API_VERSION in api_version and module.params["personality"]:
                _set_host_personality(module, array)
            if (
                PREFERRED_ARRAY_API_VERSION in api_version
                and module.params["preferred_array"]
            ):
                _set_preferred_array(module, array)
            if module.params["host_user"] or module.params["target_user"]:
                _set_chap_security(module, array)
            if module.params["volume"]:
                if module.params["lun"]:
                    array.connect_host(
                        module.params["name"],
                        module.params["volume"],
                        lun=module.params["lun"],
                    )
                else:
                    array.connect_host(module.params["name"], module.params["volume"])
        except Exception:
            module.fail_json(
                msg="Host {0} configuration failed.".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def update_host(module, array):
    """Modify a host"""
    changed = False
    renamed = False
    vlan_changed = False
    if module.params["state"] == "present":
        if module.params["vlan"]:
            vlan_changed = _update_vlan(module)
        if module.params["rename"]:
            if not rename_exists(module, array):
                if not module.check_mode:
                    try:
                        array.rename_host(
                            module.params["name"], module.params["rename"]
                        )
                        module.params["name"] = module.params["rename"]
                        renamed = True
                    except Exception:
                        module.fail_json(
                            msg="Rename to {0} failed.".format(module.params["rename"])
                        )
            else:
                module.warn(
                    "Rename failed. Target hostname {0} already exists. "
                    "Continuing with any other changes...".format(
                        module.params["rename"]
                    )
                )
        init_changed = vol_changed = pers_changed = pref_changed = chap_changed = False
        volumes = array.list_host_connections(module.params["name"])
        if module.params["iqn"] or module.params["wwns"] or module.params["nqn"]:
            init_changed = _update_host_initiators(module, array)
        if module.params["volume"]:
            current_vols = [vol["vol"] for vol in volumes]
            if not module.params["volume"] in current_vols:
                vol_changed = _connect_new_volume(module, array)
        api_version = array._list_available_rest_versions()
        if AC_REQUIRED_API_VERSION in api_version:
            if module.params["personality"]:
                pers_changed = _update_host_personality(module, array)
        if PREFERRED_ARRAY_API_VERSION in api_version:
            if module.params["preferred_array"]:
                pref_changed = _update_preferred_array(module, array)
        if module.params["target_user"] or module.params["host_user"]:
            chap_changed = _update_chap_security(module, array)
        changed = (
            init_changed
            or vol_changed
            or pers_changed
            or pref_changed
            or chap_changed
            or vlan_changed
            or renamed
        )
    else:
        if module.params["volume"]:
            volumes = array.list_host_connections(module.params["name"])
            current_vols = [vol["vol"] for vol in volumes]
            if module.params["volume"] in current_vols:
                vol_changed = _disconnect_volume(module, array)
            changed = vol_changed
    module.exit_json(changed=changed)


def delete_host(module, array):
    """Delete a host"""
    changed = True
    if not module.check_mode:
        try:
            hgroup = array.get_host(module.params["name"])["hgroup"]
            if hgroup is not None:
                array.set_hgroup(hgroup, remhostlist=[module.params["name"]])
            for vol in array.list_host_connections(module.params["name"]):
                array.disconnect_host(module.params["name"], vol["vol"])
            array.delete_host(module.params["name"])
        except Exception:
            module.fail_json(
                msg="Host {0} deletion failed".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True, aliases=["host"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            protocol=dict(
                type="str",
                choices=["fc", "iscsi", "nvme", "mixed"],
                removed_from_collection="1.13",
                removed_in_version="2.0.0",
            ),
            nqn=dict(type="list", elements="str"),
            iqn=dict(type="list", elements="str"),
            wwns=dict(type="list", elements="str"),
            host_password=dict(type="str", no_log=True),
            host_user=dict(type="str"),
            target_password=dict(type="str", no_log=True),
            target_user=dict(type="str"),
            volume=dict(type="str"),
            rename=dict(type="str"),
            lun=dict(type="int"),
            count=dict(type="int"),
            start=dict(type="int", default=0),
            digits=dict(type="int", default=1),
            suffix=dict(type="str"),
            personality=dict(
                type="str",
                default="",
                choices=[
                    "hpux",
                    "vms",
                    "aix",
                    "esxi",
                    "solaris",
                    "hitachi-vsp",
                    "oracle-vm-server",
                    "delete",
                    "",
                ],
            ),
            preferred_array=dict(type="list", elements="str"),
            vlan=dict(type="str"),
        )
    )

    required_together = [
        ["host_password", "host_user"],
        ["target_password", "target_user"],
    ]

    module = AnsibleModule(
        argument_spec, supports_check_mode=True, required_together=required_together
    )

    array = get_system(module)
    pattern = re.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
    if module.params["rename"]:
        if not pattern.match(module.params["rename"]):
            module.fail_json(
                msg="Rename value {0} does not conform to naming convention".format(
                    module.params["rename"]
                )
            )
    if not pattern.match(module.params["name"]):
        module.fail_json(
            msg="Host name {0} does not conform to naming convention".format(
                module.params["name"]
            )
        )
    if _is_cbs(array):
        if module.params["wwns"] or module.params["nqn"]:
            module.fail_json(msg="Cloud Block Store only supports iSCSI as a protocol")
    api_version = array._list_available_rest_versions()
    if module.params["nqn"] is not None and NVME_API_VERSION not in api_version:
        module.fail_json(msg="NVMe protocol not supported. Please upgrade your array.")
    state = module.params["state"]
    if module.params["suffix"]:
        suffix_len = len(module.params["suffix"])
    else:
        suffix_len = 0
    if module.params["vlan"]:
        if not HAS_PURESTORAGE:
            module.fail_json(
                msg="py-pure-client sdk is required to support 'vlan' parameter"
            )
        if VLAN_VERSION not in api_version:
            module.fail_json(
                msg="'vlan' parameter is not supported until Purity//FA 6.3.4 or higher"
            )
        if not module.params["vlan"] in ["any", "untagged"]:
            try:
                vlan = int(module.params["vlan"])
                if vlan not in range(1, 4094):
                    module.fail_json(
                        msg="VLAN must be set to a number between 1 and 4094"
                    )
            except Exception:
                module.fail_json(
                    msg="Invalid string for VLAN. Must be 'any', 'untagged' or a number between 1 and 4094"
                )
    if module.params["count"]:
        if not HAS_PURESTORAGE:
            module.fail_json(
                msg="py-pure-client sdk is required to support 'count' parameter"
            )
        if MULTI_HOST_VERSION not in api_version:
            module.fail_json(
                msg="'count' parameter is not supported until Purity//FA 6.0.0 or higher"
            )
        if module.params["digits"] and module.params["digits"] not in range(1, 10):
            module.fail_json(msg="'digits' must be in the range of 1 to 10")
        if module.params["start"] < 0:
            module.fail_json(msg="'start' must be a positive number")
        if not pattern.match(module.params["name"]):
            module.fail_json(
                msg="Host name pattern {0} does not conform to naming convention".format(
                    module.params["name"]
                )
            )
        elif module.params["suffix"] and not pattern.match(module.params["suffix"]):
            module.fail_json(
                msg="Suffix pattern {0} does not conform to naming convention".format(
                    module.params["suffix"]
                )
            )
        elif (
            len(module.params["name"])
            + max(
                len(str(module.params["count"] + module.params["start"])),
                module.params["digits"],
            )
            + suffix_len
            > 63
        ):
            module.fail_json(msg="Host name length exceeds maximum allowed")
        host = get_multi_hosts(module)
        if not host and state == "present":
            make_multi_hosts(module)
    else:
        host = get_host(module, array)
        if module.params["lun"] and not 1 <= module.params["lun"] <= 4095:
            module.fail_json(
                msg="LUN ID of {0} is out of range (1 to 4095)".format(
                    module.params["lun"]
                )
            )
        if module.params["volume"]:
            try:
                array.get_volume(module.params["volume"])
            except Exception:
                module.exit_json(changed=False)
        if module.params["preferred_array"]:
            try:
                if module.params["preferred_array"] != ["delete"]:
                    all_connected_arrays = array.list_array_connections()
                    if not all_connected_arrays:
                        module.fail_json(
                            msg="No target arrays connected to source array - preferred arrays not possible."
                        )
                    else:
                        current_arrays = [array.get()["array_name"]]
                        api_version = array._list_available_rest_versions()
                        if NVME_API_VERSION in api_version:
                            for current_array in range(0, len(all_connected_arrays)):
                                if (
                                    all_connected_arrays[current_array]["type"]
                                    == "sync-replication"
                                ):
                                    current_arrays.append(
                                        all_connected_arrays[current_array][
                                            "array_name"
                                        ]
                                    )
                        else:
                            for current_array in range(0, len(all_connected_arrays)):
                                if all_connected_arrays[current_array]["type"] == [
                                    "sync-replication"
                                ]:
                                    current_arrays.append(
                                        all_connected_arrays[current_array][
                                            "array_name"
                                        ]
                                    )
                    for array_to_connect in range(
                        0, len(module.params["preferred_array"])
                    ):
                        if (
                            module.params["preferred_array"][array_to_connect]
                            not in current_arrays
                        ):
                            module.fail_json(
                                msg="Array {0} is not a synchronously connected array.".format(
                                    module.params["preferred_array"][array_to_connect]
                                )
                            )
            except Exception:
                module.fail_json(msg="Failed to get existing array connections.")

        if host is None and state == "present" and not module.params["rename"]:
            make_host(module, array)
        elif host is None and state == "present" and module.params["rename"]:
            module.exit_json(changed=False)
        elif host and state == "present":
            update_host(module, array)
        elif host and state == "absent" and module.params["volume"]:
            update_host(module, array)
        elif host and state == "absent":
            delete_host(module, array)
        elif host is None and state == "absent":
            module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
