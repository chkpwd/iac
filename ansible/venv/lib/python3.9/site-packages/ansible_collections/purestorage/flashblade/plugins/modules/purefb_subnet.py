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


DOCUMENTATION = """
---
module: purefb_subnet
version_added: "1.0.0"
short_description:  Manage network subnets in a Pure Storage FlashBlade
description:
    - This module manages network subnets on Pure Storage FlashBlade.
author: Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
      - Subnet Name.
    required: true
    type: str
  state:
    description:
      - Create, delete or modifies a subnet.
    required: false
    default: present
    choices: [ "present", "absent" ]
    type: str
  lag:
    description:
      - Name of the Link Aggreation Group to use for the subnet.
    default: uplink
    type: str
    version_added: "1.7.0"
  gateway:
    description:
      - IPv4 or IPv6 address of subnet gateway.
    required: false
    type: str
  mtu:
    description:
      - MTU size of the subnet. Range is 1280 to 9216.
    required: false
    default: 1500
    type: int
  prefix:
    description:
      - IPv4 or IPv6 address associated with the subnet.
      - Supply the prefix length (CIDR) as well as the IP address.
      - Required for subnet creation.
    required: false
    type: str
  vlan:
    description:
      - VLAN ID of the subnet.
    required: false
    default: 0
    type: int
extends_documentation_fragment:
    - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = """
- name: Create new network subnet named foo
  purestorage.flashblade.purefb_subnet:
    name: foo
    prefix: "10.21.200.3/24"
    gateway: 10.21.200.1
    mtu: 9000
    vlan: 2200
    lag: bar
    state: present
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Change configuration of existing subnet foo
  purestorage.flashblade.purefb_subnet:
    name: foo
    state: present
    prefix: "10.21.100.3/24"
    gateway: 10.21.100.1
    mtu: 1500
    address: 10.21.200.123
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641

- name: Delete network subnet named foo
  purestorage.flashblade.purefb_subnet:
    name: foo
    state: absent
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641"""

RETURN = """
"""

HAS_PURITY_FB = True
try:
    from purity_fb import Subnet, Reference
except ImportError:
    HAS_PURITY_FB = False

try:
    import netaddr

    HAS_NETADDR = True
except ImportError:
    HAS_NETADDR = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_blade,
    purefb_argument_spec,
)


MINIMUM_API_VERSION = "1.3"


def get_subnet(module, blade):
    """Return Subnet or None"""
    subnet = []
    subnet.append(module.params["name"])
    try:
        res = blade.subnets.list_subnets(names=subnet)
        return res.items[0]
    except Exception:
        return None


def create_subnet(module, blade):
    """Create Subnet"""
    changed = True
    if not module.params["prefix"]:
        module.fail_json(msg="prefix is required for subnet creation")
    if not module.check_mode:
        subnet = []
        subnet.append(module.params["name"])
        try:
            if module.params["gateway"]:
                blade.subnets.create_subnets(
                    names=subnet,
                    subnet=Subnet(
                        prefix=module.params["prefix"],
                        vlan=module.params["vlan"],
                        mtu=module.params["mtu"],
                        gateway=module.params["gateway"],
                        link_aggregation_group=Reference(name=module.params["lag"]),
                    ),
                )
            else:
                blade.subnets.create_subnets(
                    names=subnet,
                    subnet=Subnet(
                        prefix=module.params["prefix"],
                        vlan=module.params["vlan"],
                        mtu=module.params["mtu"],
                        link_aggregation_group=Reference(name=module.params["lag"]),
                    ),
                )
        except Exception:
            module.fail_json(
                msg="Failed to create subnet {0}. Confirm supplied parameters".format(
                    module.params["name"]
                )
            )
    module.exit_json(changed=changed)


def modify_subnet(module, blade):
    """Modify Subnet settings"""
    changed = False
    subnet = get_subnet(module, blade)
    subnet_new = []
    subnet_new.append(module.params["name"])
    if module.params["prefix"]:
        if module.params["prefix"] != subnet.prefix:
            changed = True
            if not module.check_mode:
                try:
                    blade.subnets.update_subnets(
                        names=subnet_new, subnet=Subnet(prefix=module.params["prefix"])
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to change subnet {0} prefix to {1}".format(
                            module.params["name"], module.params["prefix"]
                        )
                    )
    if module.params["vlan"]:
        if module.params["vlan"] != subnet.vlan:
            changed = True
            if not module.check_mode:
                try:
                    blade.subnets.update_subnets(
                        names=subnet_new, subnet=Subnet(vlan=module.params["vlan"])
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to change subnet {0} VLAN to {1}".format(
                            module.params["name"], module.params["vlan"]
                        )
                    )
    if module.params["gateway"]:
        if module.params["gateway"] != subnet.gateway:
            changed = True
            if not module.check_mode:
                try:
                    blade.subnets.update_subnets(
                        names=subnet_new,
                        subnet=Subnet(gateway=module.params["gateway"]),
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to change subnet {0} gateway to {1}".format(
                            module.params["name"], module.params["gateway"]
                        )
                    )
    if module.params["mtu"]:
        if module.params["mtu"] != subnet.mtu:
            changed = True
            if not module.check_mode:
                try:
                    blade.subnets.update_subnets(
                        names=subnet_new, subnet=Subnet(mtu=module.params["mtu"])
                    )
                    changed = True
                except Exception:
                    module.fail_json(
                        msg="Failed to change subnet {0} MTU to {1}".format(
                            module.params["name"], module.params["mtu"]
                        )
                    )
    module.exit_json(changed=changed)


def delete_subnet(module, blade):
    """Delete Subnet"""
    changed = True
    if not module.check_mode:
        subnet = []
        subnet.append(module.params["name"])
        try:
            blade.subnets.delete_subnets(names=subnet)
        except Exception:
            module.fail_json(
                msg="Failed to delete subnet {0}".format(module.params["name"])
            )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default="present", choices=["present", "absent"]),
            gateway=dict(),
            lag=dict(type="str", default="uplink"),
            mtu=dict(type="int", default=1500),
            prefix=dict(),
            vlan=dict(type="int", default=0),
        )
    )

    required_if = [["state", "present", ["prefix"]]]

    module = AnsibleModule(
        argument_spec, required_if=required_if, supports_check_mode=True
    )

    if not HAS_PURITY_FB:
        module.fail_json(msg="purity_fb sdk is required for this module")

    if not HAS_NETADDR:
        module.fail_json(msg="netaddr module is required")

    state = module.params["state"]
    blade = get_blade(module)
    api_version = blade.api_version.list_versions().versions
    if MINIMUM_API_VERSION not in api_version:
        module.fail_json(msg="Upgrade Purity//FB to enable this module")
    subnet = get_subnet(module, blade)
    try:
        blade.link_aggregation_groups.list_link_aggregation_groups(
            names=[module.params["lag"]]
        )
    except Exception:
        module.fail_json(msg="LAG {0} does not exist.".format(module.params["lag"]))

    if state == "present":
        if not (1280 <= module.params["mtu"] <= 9216):
            module.fail_json(
                msg="MTU {0} is out of range (1280 to 9216)".format(
                    module.params["mtu"]
                )
            )
        if not (0 <= module.params["vlan"] <= 4094):
            module.fail_json(
                msg="VLAN ID {0} is out of range (0 to 4094)".format(
                    module.params["vlan"]
                )
            )
        if module.params["gateway"]:
            if netaddr.IPAddress(module.params["gateway"]) not in netaddr.IPNetwork(
                module.params["prefix"]
            ):
                module.fail_json(msg="Gateway and subnet are not compatible.")
        subnets = blade.subnets.list_subnets()
        nrange = netaddr.IPSet([module.params["prefix"]])
        for sub in range(0, len(subnets.items)):
            if (
                subnets.items[sub].vlan == module.params["vlan"]
                and subnets.items[sub].name != module.params["name"]
            ):
                module.fail_json(
                    msg="VLAN ID {0} is already in use.".format(module.params["vlan"])
                )
            if (
                nrange & netaddr.IPSet([subnets.items[sub].prefix])
                and subnets.items[sub].name != module.params["name"]
            ):
                module.fail_json(msg="Prefix CIDR overlaps with existing subnet.")

    if state == "present" and not subnet:
        create_subnet(module, blade)
    elif state == "present" and subnet:
        modify_subnet(module, blade)
    elif state == "absent" and subnet:
        delete_subnet(module, blade)
    elif state == "absent" and not subnet:
        module.exit_json(changed=False)


if __name__ == "__main__":
    main()
