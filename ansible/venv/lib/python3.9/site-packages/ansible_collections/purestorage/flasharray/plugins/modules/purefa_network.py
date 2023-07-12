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
module: purefa_network
short_description:  Manage network interfaces in a Pure Storage FlashArray
version_added: '1.0.0'
description:
    - This module manages the physical and virtual network interfaces on a Pure Storage FlashArray.
    - To manage VLAN interfaces use the I(purestorage.flasharray.purefa_vlan) module.
    - To manage network subnets use the I(purestorage.flasharray.purefa_subnet) module.
    - To remove an IP address from a non-management port use 0.0.0.0/0
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Interface name (physical or virtual).
    required: true
    type: str
  state:
    description:
      - State of existing interface (on/off).
    required: false
    default: present
    choices: [ "present", "absent" ]
    type: str
  address:
    description:
      - IPv4 or IPv6 address of interface in CIDR notation.
      - To remove an IP address from a non-management port use 0.0.0.0/0
    required: false
    type: str
  gateway:
    description:
      - IPv4 or IPv6 address of interface gateway.
    required: false
    type: str
  mtu:
    description:
      - MTU size of the interface. Range is 1280 to 9216.
    required: false
    default: 1500
    type: int
  servicelist:
    description:
      - Assigns the specified (comma-separated) service list to one or more specified interfaces.
      - Replaces the previous service list.
      - Supported service lists depend on whether the network interface is Ethernet or Fibre Channel.
      - Note that I(system) is only valid for Cloud Block Store.
    elements: str
    type: list
    choices: [ "replication", "management", "ds", "file", "iscsi", "scsi-fc", "nvme-fc", "nvme-tcp", "nvme-roce", "system"]
    version_added: '1.15.0'
extends_documentation_fragment:
    - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = """
- name: Configure and enable network interface ct0.eth8
  purestorage.flasharray.purefa_network:
    name: ct0.eth8
    gateway: 10.21.200.1
    address: "10.21.200.18/24"
    mtu: 9000
    state: present
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Disable physical interface ct1.eth2
  purestorage.flasharray.purefa_network:
    name: ct1.eth2
    state: absent
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Enable virtual network interface vir0
  purestorage.flasharray.purefa_network:
    name: vir0
    state: present
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Remove an IP address from iSCSI interface ct0.eth4
  purestorage.flasharray.purefa_network:
    name: ct0.eth4
    address: 0.0.0.0/0
    gateway: 0.0.0.0
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40

- name: Change service list for FC interface ct0.fc1
  purestorage.flasharray.purefa_network:
    name: ct0.fc1
    servicelist:
      - replication
    fa_url: 10.10.10.2
    api_token: c6033033-fe69-2515-a9e8-966bb7fe4b40
"""

RETURN = """
"""

try:
    from netaddr import IPAddress, IPNetwork

    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False

try:
    from pypureclient.flasharray import NetworkInterfacePatch

    HAS_PYPURECLIENT = True
except ImportError:
    HAS_PYPURECLIENT = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    get_array,
    purefa_argument_spec,
)

FC_ENABLE_API = "2.4"


def _is_cbs(array, is_cbs=False):
    """Is the selected array a Cloud Block Store"""
    model = array.get(controllers=True)[0]["model"]
    is_cbs = bool("CBS" in model)
    return is_cbs


def _get_fc_interface(module, array):
    """Return FC Interface or None"""
    interface = {}
    interface_list = array.get_network_interfaces(names=[module.params["name"]])
    if interface_list.status_code == 200:
        interface = list(interface_list.items)[0]
        return interface
    else:
        return None


def _get_interface(module, array):
    """Return Network Interface or None"""
    interface = {}
    if module.params["name"][0] == "v":
        try:
            interface = array.get_network_interface(module.params["name"])
        except Exception:
            return None
    else:
        try:
            interfaces = array.list_network_interfaces()
        except Exception:
            return None
        for ints in range(0, len(interfaces)):
            if interfaces[ints]["name"] == module.params["name"]:
                interface = interfaces[ints]
                break
    return interface


def update_fc_interface(module, array, interface, api_version):
    """Modify FC Interface settings"""
    changed = False
    if FC_ENABLE_API in api_version:
        if not interface.enabled and module.params["state"] == "present":
            changed = True
            if not module.check_mode:
                network = NetworkInterfacePatch(enabled=True, override_npiv_check=True)
                res = array.patch_network_interfaces(
                    names=[module.params["name"]], network=network
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to enable interface {0}.".format(
                            module.params["name"]
                        )
                    )
        if interface.enabled and module.params["state"] == "absent":
            changed = True
            if not module.check_mode:
                network = NetworkInterfacePatch(enabled=False, override_npiv_check=True)
                res = array.patch_network_interfaces(
                    names=[module.params["name"]], network=network
                )
                if res.status_code != 200:
                    module.fail_json(
                        msg="Failed to disable interface {0}.".format(
                            module.params["name"]
                        )
                    )
    if module.params["servicelist"] and sorted(module.params["servicelist"]) != sorted(
        interface.services
    ):
        changed = True
        if not module.check_mode:
            network = NetworkInterfacePatch(services=module.params["servicelist"])
            res = array.patch_network_interfaces(
                names=[module.params["name"]], network=network
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="Failed to update interface service list {0}. Error: {1}".format(
                        module.params["name"], res.errors[0].message
                    )
                )

    module.exit_json(changed=changed)


def update_interface(module, array, interface):
    """Modify Interface settings"""
    changed = False
    current_state = {
        "mtu": interface["mtu"],
        "gateway": interface["gateway"],
        "address": interface["address"],
        "netmask": interface["netmask"],
        "services": sorted(interface["services"]),
    }
    if not module.params["servicelist"]:
        services = sorted(interface["services"])
    else:
        services = sorted(module.params["servicelist"])
    if not module.params["address"]:
        address = interface["address"]
    else:
        if module.params["gateway"]:
            if module.params["gateway"] and module.params["gateway"] not in IPNetwork(
                module.params["address"]
            ):
                module.fail_json(msg="Gateway and subnet are not compatible.")
            elif not module.params["gateway"] and interface["gateway"] not in [
                None,
                IPNetwork(module.params["address"]),
            ]:
                module.fail_json(msg="Gateway and subnet are not compatible.")
        address = str(module.params["address"].split("/", 1)[0])
    ip_version = str(IPAddress(address).version)
    if not module.params["mtu"]:
        mtu = interface["mtu"]
    else:
        if not 1280 <= module.params["mtu"] <= 9216:
            module.fail_json(
                msg="MTU {0} is out of range (1280 to 9216)".format(
                    module.params["mtu"]
                )
            )
        else:
            mtu = module.params["mtu"]
    if module.params["address"]:
        netmask = str(IPNetwork(module.params["address"]).netmask)
    else:
        netmask = interface["netmask"]
    if not module.params["gateway"]:
        gateway = interface["gateway"]
    else:
        cidr = str(IPAddress(netmask).netmask_bits())
        full_addr = address + "/" + cidr
        if module.params["gateway"] not in IPNetwork(full_addr):
            module.fail_json(msg="Gateway and subnet are not compatible.")
        gateway = module.params["gateway"]
    if ip_version == "6":
        netmask = str(IPAddress(netmask).netmask_bits())
    new_state = {
        "address": address,
        "mtu": mtu,
        "gateway": gateway,
        "netmask": netmask,
        "services": services,
    }
    if new_state != current_state:
        changed = True
        if (
            "management" in interface["services"] or "app" in interface["services"]
        ) and address == "0.0.0.0/0":
            module.fail_json(
                msg="Removing IP address from a management or app port is not supported"
            )
        if not module.check_mode:
            try:
                if new_state["gateway"] is not None:
                    array.set_network_interface(
                        interface["name"],
                        address=new_state["address"],
                        mtu=new_state["mtu"],
                        netmask=new_state["netmask"],
                        gateway=new_state["gateway"],
                    )
                else:
                    array.set_network_interface(
                        interface["name"],
                        address=new_state["address"],
                        mtu=new_state["mtu"],
                        netmask=new_state["netmask"],
                    )
            except Exception:
                module.fail_json(
                    msg="Failed to change settings for interface {0}.".format(
                        interface["name"]
                    )
                )
    if not interface["enabled"] and module.params["state"] == "present":
        changed = True
        if not module.check_mode:
            try:
                array.enable_network_interface(interface["name"])
            except Exception:
                module.fail_json(
                    msg="Failed to enable interface {0}.".format(interface["name"])
                )
    if interface["enabled"] and module.params["state"] == "absent":
        changed = True
        if not module.check_mode:
            try:
                array.disable_network_interface(interface["name"])
            except Exception:
                module.fail_json(
                    msg="Failed to disable interface {0}.".format(interface["name"])
                )
    if (
        module.params["servicelist"]
        and sorted(module.params["servicelist"]) != interface["services"]
    ):
        api_version = array._list_available_rest_versions()
        if FC_ENABLE_API in api_version:
            if HAS_PYPURECLIENT:
                array = get_array(module)
                changed = True
                if not module.check_mode:
                    network = NetworkInterfacePatch(
                        services=module.params["servicelist"]
                    )
                    res = array.patch_network_interfaces(
                        names=[module.params["name"]], network=network
                    )
                    if res.status_code != 200:
                        module.fail_json(
                            msg="Failed to update interface service list {0}. Error: {1}".format(
                                module.params["name"], res.errors[0].message
                            )
                        )
            else:
                module.warn_json(
                    "Servicelist not update as pypureclient module is required"
                )

    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["present", "absent"]),
            address=dict(type="str"),
            gateway=dict(type="str"),
            mtu=dict(type="int", default=1500),
            servicelist=dict(
                type="list",
                elements="str",
                choices=[
                    "replication",
                    "management",
                    "ds",
                    "file",
                    "iscsi",
                    "scsi-fc",
                    "nvme-fc",
                    "nvme-tcp",
                    "nvme-roce",
                    "system",
                ],
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_NETADDR:
        module.fail_json(msg="netaddr module is required")

    array = get_system(module)
    api_version = array._list_available_rest_versions()
    if not _is_cbs(array):
        if module.params["servicelist"] and "system" in module.params["servicelist"]:
            module.fail_json(
                msg="Only Cloud Block Store supports the 'system' service type"
            )
    if "." in module.params["name"]:
        if module.params["name"].split(".")[1][0].lower() == "f":
            if not HAS_PYPURECLIENT:
                module.fail_json(msg="pypureclient module is required")
            array = get_array(module)
            interface = _get_fc_interface(module, array)
            if not interface:
                module.fail_json(msg="Invalid network interface specified.")
            else:
                update_fc_interface(module, array, interface, api_version)
        else:
            interface = _get_interface(module, array)
            if not interface:
                module.fail_json(msg="Invalid network interface specified.")
            else:
                update_interface(module, array, interface)
    else:
        interface = _get_interface(module, array)
        if not interface:
            module.fail_json(msg="Invalid network interface specified.")
        else:
            update_interface(module, array, interface)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
