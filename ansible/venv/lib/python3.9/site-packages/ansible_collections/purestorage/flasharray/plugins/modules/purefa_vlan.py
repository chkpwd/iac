#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
---
module: purefa_vlan
version_added: '1.0.0'
short_description:  Manage network VLAN interfaces in a Pure Storage FlashArray
description:
    - This module manages the VLAN network interfaces on a Pure Storage FlashArray.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Interface name, including controller indentifier.
      - VLANs are only supported on iSCSI, NVMe-RoCE and file
        physical interfaces
    required: true
    type: str
  state:
    description:
      - State of existing interface (on/off).
    required: false
    default: present
    choices: [ "present", "absent" ]
    type: str
  enabled:
    description:
      - Define if VLAN interface is enabled or not.
    required: false
    default: true
    type: bool
  address:
    description:
      - IPv4 or IPv6 address of interface.
    required: false
    type: str
  subnet:
    description:
      - Name of subnet interface associated with.
    required: true
    type: str
extends_documentation_fragment:
    - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = """
- name: Configure and enable VLAN interface ct0.eth8 for subnet test
  purestorage.flasharray.purefa_vlan:
    name: ct0.eth8
    subnet: test
    address: 10.21.200.18
    state: present
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Disable VLAN interface for subnet test on ct1.eth2
  purestorage.flasharray.purefa_vlan:
    name: ct1.eth2
    subnet: test
    enabled: false
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Delete VLAN inteface for subnet test on ct0.eth4
  purestorage.flasharray.purefa_vlan:
    name: ct0.eth4
    subnet: test
    state: absent
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40"""

RETURN = """
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


def _get_subnet(module, array):
    """Return subnet or None"""
    subnet = {}
    try:
        subnet = array.get_subnet(module.params["subnet"])
    except Exception:
        return None
    return subnet


def _get_interface(module, array):
    """Return Interface or None"""
    interface = {}
    if "ct" in module.params["name"]:
        try:
            interfaces = array.list_network_interfaces()
        except Exception:
            return None
        for ints in range(0, len(interfaces)):
            if interfaces[ints]["name"] == module.params["name"]:
                interface = interfaces[ints]
                break
    return interface


def _get_vif(array, interface, subnet):
    """Return VLAN Interface or None"""
    vif_info = {}
    vif_name = interface["name"] + "." + str(subnet["vlan"])
    try:
        interfaces = array.list_network_interfaces()
    except Exception:
        return None
    for ints in range(0, len(interfaces)):
        if interfaces[ints]["name"] == vif_name:
            vif_info = interfaces[ints]
            break
    return vif_info


def create_vif(module, array, interface, subnet):
    """Create VLAN Interface"""
    changed = True
    if not module.check_mode:
        vif_name = interface["name"] + "." + str(subnet["vlan"])
        if module.params["address"]:
            try:
                array.create_vlan_interface(
                    vif_name, module.params["subnet"], address=module.params["address"]
                )
            except Exception:
                module.fail_json(
                    msg="Failed to create VLAN interface {0}.".format(vif_name)
                )
        else:
            try:
                array.create_vlan_interface(vif_name, module.params["subnet"])
            except Exception:
                module.fail_json(
                    msg="Failed to create VLAN interface {0}.".format(vif_name)
                )
        if not module.params["enabled"]:
            try:
                array.set_network_interface(vif_name, enabled=False)
            except Exception:
                module.fail_json(
                    msg="Failed to disable VLAN interface {0} on creation.".format(
                        vif_name
                    )
                )
    module.exit_json(changed=changed)


def update_vif(module, array, interface, subnet):
    """Modify VLAN Interface settings"""
    changed = False
    vif_info = _get_vif(array, interface, subnet)
    vif_name = vif_info["name"]
    if module.params["address"]:
        if module.params["address"] != vif_info["address"]:
            changed = True
            if not module.check_mode:
                try:
                    array.set_network_interface(
                        vif_name, address=module.params["address"]
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to change IP address for VLAN interface {0}.".format(
                            subnet
                        )
                    )

    if module.params["enabled"] != vif_info["enabled"]:
        if module.params["enabled"]:
            changed = True
            if not module.check_mode:
                try:
                    array.set_network_interface(vif_name, enabled=True)
                except Exception:
                    module.fail_json(
                        msg="Failed to enable VLAN interface {0}.".format(vif_name)
                    )
        else:
            changed = True
            if not module.check_mode:
                try:
                    array.set_network_interface(vif_name, enabled=False)
                except Exception:
                    module.fail_json(
                        msg="Failed to disable VLAN interface {0}.".format(vif_name)
                    )

    module.exit_json(changed=changed)


def delete_vif(module, array, subnet):
    """Delete VLAN Interface"""
    changed = True
    if not module.check_mode:
        vif_name = module.params["name"] + "." + str(subnet["vlan"])
        try:
            array.delete_vlan_interface(vif_name)
        except Exception:
            module.fail_json(msg="Failed to delete VLAN inerface {0}".format(vif_name))
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            subnet=dict(type="str", required=True),
            enabled=dict(type="bool", default=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            address=dict(type="str"),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    state = module.params["state"]
    array = get_system(module)
    subnet = _get_subnet(module, array)
    interface = _get_interface(module, array)
    if not subnet:
        module.fail_json(msg="Invalid subnet specified.")
    if not interface:
        module.fail_json(msg="Invalid interface specified.")
    if ("iscsi" or "nvme-roce" or "nvme-tcp" or "file") not in interface["services"]:
        module.fail_json(
            msg="Invalid interface specified - must have service type of iSCSI, NVMe-RoCE, NVMe-TCP or file enabled."
        )
    if subnet["vlan"]:
        vif_name = module.params["name"] + "." + str(subnet["vlan"])
    vif = bool(vif_name in subnet["interfaces"])

    if state == "present" and not vif:
        create_vif(module, array, interface, subnet)
    elif state == "present" and vif:
        update_vif(module, array, interface, subnet)
    elif state == "absent" and vif:
        delete_vif(module, array, subnet)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
