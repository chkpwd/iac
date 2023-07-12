#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2023, Simon Dodsley (simon@purestorage.com), Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_se
version_added: '1.0.0'
short_description:  Manage storage endpoints in Pure Storage Fusion
description:
- Create or delete storage endpoints in Pure Storage Fusion.
notes:
- Supports C(check_mode).
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the storage endpoint.
    type: str
    required: true
  display_name:
    description:
    - The human name of the storage endpoint.
    - If not provided, defaults to I(name).
    type: str
  state:
    description:
    - Define whether the storage endpoint should exist or not.
    type: str
    default: present
    choices: [ absent, present ]
  region:
    description:
    - The name of the region the availability zone is in
    type: str
    required: true
  availability_zone:
    aliases: [ az ]
    description:
    - The name of the availability zone for the storage endpoint.
    type: str
    required: true
  endpoint_type:
    description:
    - "DEPRECATED: Will be removed in version 2.0.0"
    - Type of the storage endpoint. Only iSCSI is available at the moment.
    type: str
  iscsi:
    description:
    - List of discovery interfaces.
    type: list
    elements: dict
    suboptions:
      address:
        description:
        - IP address to be used in the subnet of the storage endpoint.
        - IP address must include a CIDR notation.
        - Only IPv4 is supported at the moment.
        type: str
      gateway:
        description:
        - Address of the subnet gateway.
        type: str
      network_interface_groups:
        description:
        - List of network interface groups to assign to the address.
        type: list
        elements: str
  cbs_azure_iscsi:
    description:
    - CBS Azure iSCSI
    type: dict
    suboptions:
      storage_endpoint_collection_identity:
        description:
        - The Storage Endpoint Collection Identity which belongs to the Azure entities.
        type: str
      load_balancer:
        description:
        - The Load Balancer id which gives permissions to CBS array applications to modify the Load Balancer.
        type: str
      load_balancer_addresses:
        description:
        - The IPv4 addresses of the Load Balancer.
        type: list
        elements: str
  network_interface_groups:
    description:
    - "DEPRECATED: Will be removed in version 2.0.0"
    - List of network interface groups to assign to the storage endpoints.
    type: list
    elements: str
  addresses:
    description:
    - "DEPRECATED: Will be removed in version 2.0.0"
    - List of IP addresses to be used in the subnet of the storage endpoint.
    - IP addresses must include a CIDR notation.
    - Only IPv4 is supported at the moment.
    type: list
    elements: str
  gateway:
    description:
    - "DEPRECATED: Will be removed in version 2.0.0"
    - Address of the subnet gateway.
    - Currently this must be provided.
    type: str

extends_documentation_fragment:
- purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Create new storage endpoint foo in AZ bar
  purestorage.fusion.fusion_se:
    name: foo
    availability_zone: bar
    region: us-west
    iscsi:
      - address: 10.21.200.124/24
        gateway: 10.21.200.1
        network_interface_groups:
          - subnet-0
      - address: 10.21.200.36/24
        gateway: 10.21.200.2
        network_interface_groups:
          - subnet-0
          - subnet-1
    state: present
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Create new CBS storage endpoint foo in AZ bar
  purestorage.fusion.fusion_se:
    name: foo
    availability_zone: bar
    region: us-west
    cbs_azure_iscsi:
      storage_endpoint_collection_identity: "/subscriptions/sub/resourcegroups/sec/providers/ms/userAssignedIdentities/secId"
      load_balancer: "/subscriptions/sub/resourcegroups/sec/providers/ms/loadBalancers/sec-lb"
      load_balancer_addresses:
        - 10.21.200.1
        - 10.21.200.2
    state: present
    app_id: key_name
    key_file: "az-admin-private-key.pem"

- name: Delete storage endpoint foo in AZ bar
  purestorage.fusion.fusion_se:
    name: foo
    availability_zone: bar
    region: us-west
    state: absent
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: (DEPRECATED) Create new storage endpoint foo in AZ bar
  purestorage.fusion.fusion_se:
    name: foo
    availability_zone: bar
    gateway: 10.21.200.1
    region: us-west
    addresses:
      - 10.21.200.124/24
      - 10.21.200.36/24
    network_interface_groups:
      - subnet-0
    state: present
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
    is_valid_network,
    is_valid_address,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.operations import (
    await_operation,
)


#######################################################################
# DEPRECATED CODE SECTION STARTS


def create_se_old(module, fusion):
    """Create Storage Endpoint"""

    se_api_instance = purefusion.StorageEndpointsApi(fusion)

    changed = True

    if not module.check_mode:
        if not module.params["display_name"]:
            display_name = module.params["name"]
        else:
            display_name = module.params["display_name"]
        ifaces = []
        for address in module.params["addresses"]:
            if module.params["gateway"]:
                iface = purefusion.StorageEndpointIscsiDiscoveryInterfacePost(
                    address=address,
                    gateway=module.params["gateway"],
                    network_interface_groups=module.params["network_interface_groups"],
                )
            else:
                iface = purefusion.StorageEndpointIscsiDiscoveryInterfacePost(
                    address=address,
                    network_interface_groups=module.params["network_interface_groups"],
                )
            ifaces.append(iface)
        op = purefusion.StorageEndpointPost(
            endpoint_type="iscsi",
            iscsi=purefusion.StorageEndpointIscsiPost(
                discovery_interfaces=ifaces,
            ),
            name=module.params["name"],
            display_name=display_name,
        )
        op = se_api_instance.create_storage_endpoint(
            op,
            region_name=module.params["region"],
            availability_zone_name=module.params["availability_zone"],
        )
        await_operation(fusion, op)

    module.exit_json(changed=changed)


# DEPRECATED CODE SECTION ENDS
#######################################################################


def get_se(module, fusion):
    """Storage Endpoint or None"""
    se_api_instance = purefusion.StorageEndpointsApi(fusion)
    try:
        return se_api_instance.get_storage_endpoint(
            region_name=module.params["region"],
            storage_endpoint_name=module.params["name"],
            availability_zone_name=module.params["availability_zone"],
        )
    except purefusion.rest.ApiException:
        return None


def create_se(module, fusion):
    """Create Storage Endpoint"""
    se_api_instance = purefusion.StorageEndpointsApi(fusion)

    if not module.check_mode:
        endpoint_type = None

        iscsi = None
        if module.params["iscsi"] is not None:
            iscsi = purefusion.StorageEndpointIscsiPost(
                discovery_interfaces=[
                    purefusion.StorageEndpointIscsiDiscoveryInterfacePost(**endpoint)
                    for endpoint in module.params["iscsi"]
                ]
            )
            endpoint_type = "iscsi"

        cbs_azure_iscsi = None
        if module.params["cbs_azure_iscsi"] is not None:
            cbs_azure_iscsi = purefusion.StorageEndpointCbsAzureIscsiPost(
                storage_endpoint_collection_identity=module.params["cbs_azure_iscsi"][
                    "storage_endpoint_collection_identity"
                ],
                load_balancer=module.params["cbs_azure_iscsi"]["load_balancer"],
                load_balancer_addresses=module.params["cbs_azure_iscsi"][
                    "load_balancer_addresses"
                ],
            )
            endpoint_type = "cbs-azure-iscsi"

        op = se_api_instance.create_storage_endpoint(
            purefusion.StorageEndpointPost(
                name=module.params["name"],
                display_name=module.params["display_name"] or module.params["name"],
                endpoint_type=endpoint_type,
                iscsi=iscsi,
                cbs_azure_iscsi=cbs_azure_iscsi,
            ),
            region_name=module.params["region"],
            availability_zone_name=module.params["availability_zone"],
        )
        await_operation(fusion, op)

    module.exit_json(changed=True)


def delete_se(module, fusion):
    """Delete Storage Endpoint"""
    se_api_instance = purefusion.StorageEndpointsApi(fusion)
    if not module.check_mode:
        op = se_api_instance.delete_storage_endpoint(
            region_name=module.params["region"],
            availability_zone_name=module.params["availability_zone"],
            storage_endpoint_name=module.params["name"],
        )
        await_operation(fusion, op)
    module.exit_json(changed=True)


def update_se(module, fusion, se):
    """Update Storage Endpoint"""

    se_api_instance = purefusion.StorageEndpointsApi(fusion)
    patches = []
    if (
        module.params["display_name"]
        and module.params["display_name"] != se.display_name
    ):
        patch = purefusion.StorageEndpointPatch(
            display_name=purefusion.NullableString(module.params["display_name"]),
        )
        patches.append(patch)

    if not module.check_mode:
        for patch in patches:
            op = se_api_instance.update_storage_endpoint(
                patch,
                region_name=module.params["region"],
                availability_zone_name=module.params["availability_zone"],
                storage_endpoint_name=module.params["name"],
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
            iscsi=dict(
                type="list",
                elements="dict",
                options=dict(
                    address=dict(type="str"),
                    gateway=dict(type="str"),
                    network_interface_groups=dict(type="list", elements="str"),
                ),
            ),
            cbs_azure_iscsi=dict(
                type="dict",
                options=dict(
                    storage_endpoint_collection_identity=dict(type="str"),
                    load_balancer=dict(type="str"),
                    load_balancer_addresses=dict(type="list", elements="str"),
                ),
            ),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            # deprecated, will be removed in 2.0.0
            endpoint_type=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            addresses=dict(
                type="list",
                elements="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            gateway=dict(
                type="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
            network_interface_groups=dict(
                type="list",
                elements="str",
                removed_in_version="2.0.0",
                removed_from_collection="purestorage.fusion",
            ),
        )
    )

    mutually_exclusive = [
        ("iscsi", "cbs_azure_iscsi"),
        # can not use both deprecated and new fields at the same time
        ("iscsi", "cbs_azure_iscsi", "addresses"),
        ("iscsi", "cbs_azure_iscsi", "gateway"),
        ("iscsi", "cbs_azure_iscsi", "network_interface_groups"),
    ]

    module = AnsibleModule(
        argument_spec,
        mutually_exclusive=mutually_exclusive,
        supports_check_mode=True,
    )
    fusion = setup_fusion(module)

    state = module.params["state"]

    if module.params["endpoint_type"] is not None:
        module.warn(
            "'endpoint_type' parameter is deprecated and will be removed in the version 2.0"
        )

    deprecated_parameters = {"addresses", "gateway", "network_interface_groups"}
    used_deprecated_parameters = [
        key
        for key in list(deprecated_parameters & module.params.keys())
        if module.params[key] is not None
    ]

    if len(used_deprecated_parameters) > 0:
        # user uses deprecated module interface
        for param_name in used_deprecated_parameters:
            module.warn(
                f"'{param_name}' parameter is deprecated and will be removed in the version 2.0"
            )

        if module.params["addresses"]:
            for address in module.params["addresses"]:
                if not is_valid_network(address):
                    module.fail_json(
                        msg=f"'{address}' is not a valid address in CIDR notation"
                    )

        sendp = get_se(module, fusion)

        if state == "present" and not sendp:
            module.fail_on_missing_params(["addresses"])
            if not (module.params["addresses"]):
                module.fail_json(
                    msg="At least one entry in 'addresses' is required to create new storage endpoint"
                )
            create_se_old(module, fusion)
        elif state == "present" and sendp:
            update_se(module, fusion, sendp)
        elif state == "absent" and sendp:
            delete_se(module, fusion)
    else:
        # user uses new module interface
        if module.params["iscsi"] is not None:
            for endpoint in module.params["iscsi"]:
                address = endpoint["address"]
                if not is_valid_network(address):
                    module.fail_json(
                        msg=f"'{address}' is not a valid address in CIDR notation"
                    )
                gateway = endpoint["gateway"]
                if not is_valid_address(gateway):
                    module.fail_json(
                        msg=f"'{gateway}' is not a valid IPv4 address notation"
                    )
        if module.params["cbs_azure_iscsi"] is not None:
            for address in module.params["cbs_azure_iscsi"]["load_balancer_addresses"]:
                if not is_valid_address(address):
                    module.fail_json(
                        msg=f"'{address}' is not a valid IPv4 address notation"
                    )

        sendp = get_se(module, fusion)

        if state == "present" and not sendp:
            if (
                module.params["iscsi"] is None
                and module.params["cbs_azure_iscsi"] is None
            ):
                module.fail_json(
                    msg="either 'iscsi' or `cbs_azure_iscsi` parameter is required when creating storage endpoint"
                )
            create_se(module, fusion)
        elif state == "present" and sendp:
            update_se(module, fusion, sendp)
        elif state == "absent" and sendp:
            delete_se(module, fusion)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
