#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2022, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_nig
version_added: '1.0.0'
short_description:  Manage Network Interface Groups in Pure Storage Fusion
description:
- Create, delete and modify network interface groups in Pure Storage Fusion.
- Currently this only supports a single tenant subnet per tenant network
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  name:
    description:
    - The name of the network interface group.
    type: str
    required: true
  display_name:
    description:
    - The human name of the network interface group.
    - If not provided, defaults to I(name).
    type: str
  state:
    description:
    - Define whether the network interface group should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone for the network interface group.
    type: str
    required: true
  region:
    description:
    - Region for the network interface group.
    type: str
    required: true
  gateway:
    description:
    - "Address of the subnet gateway.
    Currently must be a valid IPv4 address."
    type: str
  mtu:
    description:
    - MTU setting for the subnet.
    default: 1500
    type: int
  group_type:
    description:
    - The type of network interface group.
    type: str
    default: eth
    choices: [ eth ]
  prefix:
    description:
    - "Network prefix in CIDR notation.
    Required to create a new network interface group.
    Currently only IPv4 addresses with subnet mask are supported."
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new network interface group foo in AZ bar
  purestorage.fusion.fusion_nig:
    name: foo
    availability_zone: bar
    region: region1
    mtu: 9000
    gateway: 10.21.200.1
    prefix: 10.21.200.0/24
    state: present
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Delete network interface group foo in AZ bar
  purestorage.fusion.fusion_nig:
    name: foo
    availability_zone: bar
    region: region1
    state: absent
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"
"""

RETURN = r"""
"""

try:
    import fusion as purefusion
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.networking import (
    is_valid_address,
    is_valid_network,
    is_address_in_network,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)


def get_nig(module, fusion):
    """Check Network Interface Group"""
    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
    try:
        return nig_api_instance.get_network_interface_group(
            availability_zone_name=module.params["availability_zone"],
            region_name=module.params["region"],
            network_interface_group_name=module.params["name"],
        )
    except purefusion.rest.ApiException:
        return None


def create_nig(module, fusion):
    """Create Network Interface Group"""

    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)

    changed = False
    if module.params["gateway"] and not is_address_in_network(
        module.params["gateway"], module.params["prefix"]
    ):
        module.fail_json(msg="`gateway` must be an address in subnet `prefix`")

    if not module.check_mode:
        display_name = module.params["display_name"] or module.params["name"]
        if module.params["group_type"] == "eth":
            if module.params["gateway"]:
                eth = purefusion.NetworkInterfaceGroupEthPost(
                    prefix=module.params["prefix"],
                    gateway=module.params["gateway"],
                    mtu=module.params["mtu"],
                )
            else:
                eth = purefusion.NetworkInterfaceGroupEthPost(
                    prefix=module.params["prefix"],
                    mtu=module.params["mtu"],
                )
            nig = purefusion.NetworkInterfaceGroupPost(
                group_type="eth",
                eth=eth,
                name=module.params["name"],
                display_name=display_name,
            )
            op = nig_api_instance.create_network_interface_group(
                nig,
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
            )
            await_operation(fusion, op)
            changed = True
        else:
            # to prevent future unintended error
            module.warn(f"group_type={module.params['group_type']} is not implemented")

    module.exit_json(changed=changed)


def delete_nig(module, fusion):
    """Delete Network Interface Group"""
    changed = True
    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
    if not module.check_mode:
        op = nig_api_instance.delete_network_interface_group(
            availability_zone_name=module.params["availability_zone"],
            region_name=module.params["region"],
            network_interface_group_name=module.params["name"],
        )
        await_operation(fusion, op)
    module.exit_json(changed=changed)


def update_nig(module, fusion, nig):
    """Update Network Interface Group"""

    nifg_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
    patches = []
    if (
        module.params["display_name"]
        and module.params["display_name"] != nig.display_name
    ):
        patch = purefusion.NetworkInterfaceGroupPatch(
            display_name=purefusion.NullableString(module.params["display_name"]),
        )
        patches.append(patch)

    if not module.check_mode:
        for patch in patches:
            op = nifg_api_instance.update_network_interface_group(
                patch,
                availability_zone_name=module.params["availability_zone"],
                region_name=module.params["region"],
                network_interface_group_name=module.params["name"],
            )
            await_operation(fusion, op)

    changed = len(patches) != 0

    module.exit_json(changed=changed)


def main():
    """Main code"""
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            display_name=dict(type="str"),
            availability_zone=dict(type="str", required=True, aliases=["az"]),
            region=dict(type="str", required=True),
            prefix=dict(type="str"),
            gateway=dict(type="str"),
            mtu=dict(type="int", default=1500),
            group_type=dict(type="str", default="eth", choices=["eth"]),
            state=dict(type="str", default="present", choices=["absent", "present"]),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    fusion = setup_fusion(module)

    state = module.params["state"]
    if module.params["prefix"] and not is_valid_network(module.params["prefix"]):
        module.fail_json(
            msg="`prefix` '{0}' is not a valid address in CIDR notation".format(
                module.params["prefix"]
            )
        )
    if module.params["gateway"] and not is_valid_address(module.params["gateway"]):
        module.fail_json(
            msg="`gateway` '{0}' is not a valid address".format(
                module.params["gateway"]
            )
        )

    nig = get_nig(module, fusion)

    if state == "present" and not nig:
        module.fail_on_missing_params(["prefix"])
        create_nig(module, fusion)
    elif state == "present" and nig:
        update_nig(module, fusion, nig)
    elif state == "absent" and nig:
        delete_nig(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
