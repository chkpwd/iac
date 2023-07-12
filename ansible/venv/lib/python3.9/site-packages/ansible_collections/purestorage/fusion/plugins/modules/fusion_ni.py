#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2023, Andrej Pajtas (apajtas@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_ni
version_added: '1.0.0'
short_description:  Manage network interfaces in Pure Storage Fusion
description:
- Update parameters of network interfaces in Pure Storage Fusion.
notes:
- Supports C(check_mode).
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the network interface.
    type: str
    required: true
  display_name:
    description:
    - The human name of the network interface.
    - If not provided, defaults to I(name).
    type: str
  region:
    description:
    - The name of the region the availability zone is in.
    type: str
    required: true
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone for the network interface.
    type: str
    required: true
  array:
    description:
    - The name of the array the network interface belongs to.
    type: str
    required: true
  eth:
    description:
    - The IP address associated with the network interface.
    - IP address must include a CIDR notation.
    - Only IPv4 is supported at the moment.
    - Required together with `network_interface_group` parameter.
    type: str
  enabled:
    description:
    - True if network interface is in use.
    type: bool
  network_interface_group:
    description:
    - The name of the network interface group this network interface belongs to.
    type: str
extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Patch network interface
  purestorage.fusion.fusion_ni:
    name: foo
    region: us-west
    availability_zone: bar
    array: array0
    eth: 10.21.200.124/24
    enabled: true
    network_interface_group: subnet-0
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

from ansible_collections.purestorage.fusion.plugins.module_utils.getters import (
    get_array,
    get_az,
    get_region,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.networking import (
    is_valid_network,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)


def get_ni(module, fusion):
    """Get Network Interface or None"""
    ni_api_instance = purefusion.NetworkInterfacesApi(fusion)
    try:
        return ni_api_instance.get_network_interface(
            region_name=module.params["region"],
            availability_zone_name=module.params["availability_zone"],
            array_name=module.params["array"],
            net_intf_name=module.params["name"],
        )
    except purefusion.rest.ApiException:
        return None


def update_ni(module, fusion, ni):
    """Update Network Interface"""
    ni_api_instance = purefusion.NetworkInterfacesApi(fusion)

    patches = []
    if (
        module.params["display_name"]
        and module.params["display_name"] != ni.display_name
    ):
        patch = purefusion.NetworkInterfacePatch(
            display_name=purefusion.NullableString(module.params["display_name"]),
        )
        patches.append(patch)

    if module.params["enabled"] is not None and module.params["enabled"] != ni.enabled:
        patch = purefusion.NetworkInterfacePatch(
            enabled=purefusion.NullableBoolean(module.params["enabled"]),
        )
        patches.append(patch)

    if (
        module.params["network_interface_group"]
        and module.params["network_interface_group"] != ni.network_interface_group
    ):
        if module.params["eth"] and module.params["eth"] != ni.eth:
            patch = purefusion.NetworkInterfacePatch(
                eth=purefusion.NetworkInterfacePatchEth(
                    purefusion.NullableString(module.params["eth"])
                ),
                network_interface_group=purefusion.NullableString(
                    module.params["network_interface_group"]
                ),
            )
        else:
            patch = purefusion.NetworkInterfacePatch(
                network_interface_group=purefusion.NullableString(
                    module.params["network_interface_group"]
                ),
            )
        patches.append(patch)

    if not module.check_mode:
        for patch in patches:
            op = ni_api_instance.update_network_interface(
                patch,
                region_name=module.params["region"],
                availability_zone_name=module.params["availability_zone"],
                array_name=module.params["array"],
                net_intf_name=module.params["name"],
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
            region=dict(type="str", required=True),
            availability_zone=dict(type="str", required=True, aliases=["az"]),
            array=dict(type="str", required=True),
            eth=dict(type="str"),
            enabled=dict(type="bool"),
            network_interface_group=dict(type="str"),
        )
    )

    required_by = {
        "eth": "network_interface_group",
    }

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
        required_by=required_by,
    )

    fusion = setup_fusion(module)

    if module.params["eth"] and not is_valid_network(module.params["eth"]):
        module.fail_json(
            msg="`eth` '{0}' is not a valid address in CIDR notation".format(
                module.params["eth"]
            )
        )

    if not get_region(module, fusion):
        module.fail_json(
            msg="Region {0} does not exist.".format(module.params["region"])
        )

    if not get_az(module, fusion):
        module.fail_json(
            msg="Availability Zone {0} does not exist.".format(
                module.params["availability_zone"]
            )
        )

    if not get_array(module, fusion):
        module.fail_json(msg="Array {0} does not exist.".format(module.params["array"]))

    ni = get_ni(module, fusion)
    if not ni:
        module.fail_json(
            msg="Network Interface {0} does not exist".format(module.params["name"])
        )

    update_ni(module, fusion, ni)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
