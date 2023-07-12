#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_network_space
version_added: '2.12.0'
short_description: Create, Delete and Modify network spaces on Infinibox
description:
    - This module creates, deletes or modifies network spaces on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - Network space name
    required: true
  state:
    description:
      - Creates/Modifies network spaces when present. Removes when absent. Shows status when stat.
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
  interfaces:
    description:
      - A list of interfaces for the space.
    required: false
    type: list
    elements: str
  service:
    description:
      - Choose a service.
    required: false
    default: "replication"
    choices: ["replication", "NAS", "iSCSI"]
  mtu:
    description:
      - Set an MTU. If not specified, defaults to 1500 bytes.
    required: false
    type: int
  network:
    description:
      - Starting IP address.
    required: false
    type: str
  netmask:
    description:
      - Network mask.
    required: false
    type: int
  ips:
    description:
      - List of IPs.
    required: false
    default: []
    type: list
    elements: str
  rate_limit:
    description:
      - Specify the throughput limit per node.
      - The limit is specified in Mbps, megabits per second (not megabytes).
      - Note the limit affects NFS, iSCSI and async-replication traffic.
      - It does not affect sync-replication or active-active traffic.
    required: false
    type: int

extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new network space
  infini_network_space:
    name: iSCSI
    state: present
    interfaces:
        - 1680
        - 1679
        - 1678
    service: ISCSI_SERVICE
    netmask: 19
    network: 172.31.32.0
    default_gateway: 172.31.63.254
    ips:
        - 172.31.32.145
        - 172.31.32.146
        - 172.31.32.147
        - 172.31.32.148
        - 172.31.32.149
        - 172.31.32.150
    user: admin
    password: secret
    system: ibox001
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

import traceback

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    unixMillisecondsToDate,
    merge_two_dicts,
    get_net_space,
)

try:
    from infinisdk.core.exceptions import APICommandFailed
    from infinisdk.core.exceptions import ObjectNotFound
    from infi.dtypes.iqn import make_iscsi_name
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def create_empty_network_space(module, system):
    # Create network space
    network_space_name = module.params["name"]
    service = module.params["service"]
    rate_limit = module.params["rate_limit"]
    mtu = module.params["mtu"]
    network_config = {
        "netmask": module.params["netmask"],
        "network": module.params["network"],
        "default_gateway": module.params["default_gateway"],
    }
    interfaces = module.params["interfaces"]

    # print("Creating network space {0}".format(network_space_name))
    product_id = system.api.get('system/product_id')
    # print("api: {0}".format(product_id.get_result()))

    net_create_url = "network/spaces"
    net_create_data = {
        "name": network_space_name,
        "service": service,
        "network_config": network_config,
        "interfaces": interfaces,
    }
    if rate_limit:
        net_create_data["rate_limit"] = rate_limit
    if mtu:
        net_create_data["mtu"] = mtu

    net_create = system.api.post(
        path=net_create_url,
        data=net_create_data
    )
    # print("net_create: {0}".format(net_create))


@api_wrapper
def find_network_space_id(module, system):
    """
    Find the ID of this network space
    """
    network_space_name = module.params["name"]
    net_id_url = "network/spaces?name={0}&fields=id".format(network_space_name)
    net_id = system.api.get(
        path=net_id_url
    )
    result = net_id.get_json()['result'][0]
    space_id = result['id']
    # print("Network space has ID {0}".format(space_id))
    return space_id


@api_wrapper
def add_ips_to_network_space(module, system, space_id):
    network_space_name = module.params["name"]
    # print("Adding IPs to network space {0}".format(network_space_name))

    ips = module.params["ips"]
    for ip in ips:
        ip_url = "network/spaces/{0}/ips".format(space_id)
        ip_data = ip
        ip_add = system.api.post(
            path=ip_url,
            data=ip_data
        )
        # print("add_ips json: {0}".format(ip_add.get_json()))
        result = ip_add.get_json()['result']
        # print("add ip result: {0}".format(result))


@api_wrapper
def create_network_space(module, system):
    if not module.check_mode:
        # Create space
        create_empty_network_space(module, system)
        # Find space's ID
        space_id = find_network_space_id(module, system)
        # Add IPs to space
        add_ips_to_network_space(module, system, space_id)

        changed = True
    else:
        changed = False

    return changed


def update_network_space(module, system):
    """
    Update network space.
    TODO - This is incomplete and will not update the space.
    It will instead return changed=False and a message.
    To implement this we will need to find the existing space.
    For each field that we support updating, we need to compare existing
    to new values and if different update.  We will need to iterate
    over the settings or we will receive:
        Status: 400
        Code: NOT_SUPPORTED_MULTIPLE_UPDATE
    """
    changed = False
    msg = "Update is not supported yet"
    module.exit_json(changed=changed, msg=msg)

    # TODO Everything below is incomplete
    # Update network space
    network_space_name = module.params["name"]
    service = module.params["service"]
    network_config = {
        "netmask": module.params["netmask"],
        "network": module.params["network"],
        "default_gateway": module.params["default_gateway"],
    }
    interfaces = module.params["interfaces"]

    # print("Updating network space {0}".format(network_space_name))

    # Find space's ID
    space_id = find_network_space_id(module, system)

    net_url = "network/spaces/{0}".format(space_id)
    net_data = {
        "name": network_space_name,
        "service": service,
        "network_config": network_config,
        "interfaces": interfaces,
    }

    # Find existing space
    net_existing = system.api.get(path=net_url)

    net_update = system.api.put(
        path=net_url,
        data=net_data
    )
    # print("net_update: {0}".format(net_update))


def get_network_space_fields(module, network_space):
    fields = network_space.get_fields(from_cache=True, raw_value=True)

    field_dict = dict(
        name=fields["name"],
        network_space_id=fields["id"],
        netmask=fields["network_config"]["netmask"],
        network=fields["network_config"]["network"],
        default_gateway=fields["network_config"]["default_gateway"],
        interface_ids=fields["interfaces"],
        service=fields["service"],
        ips=fields["ips"],
        properties=fields["properties"],
        automatic_ip_failback=fields["automatic_ip_failback"],
        mtu=fields["mtu"],
        rate_limit=fields["rate_limit"],
    )
    return field_dict


def handle_stat(module):
    network_space_name = module.params["name"]
    system = get_system(module)
    net_space = get_net_space(module, system)

    if not net_space:
        module.fail_json(msg="Network space {0} not found".format(network_space_name))

    field_dict = get_network_space_fields(module, net_space)
    result = dict(
        changed=False, msg="Network space {0} stat found".format(network_space_name)
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    """
    If it does not already exist, create namespace. Otherwise, update namespace.
    """
    network_space_name = module.params["name"]
    system = get_system(module)
    net_space = get_net_space(module, system)
    if net_space:
        changed = update_network_space(module, net_space)
        msg = "Host {0} updated".format(network_space_name)
    else:
        changed = create_network_space(module, system)
        msg = "Network space {0} created".format(network_space_name)
    module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    """
    Remove a namespace. First, may disable and remove the namespace's IPs.
    """
    network_space_name = module.params["name"]
    system = get_system(module)
    network_space = get_net_space(module, system)
    if not network_space:
        changed = False
        msg = "Network space {0} already absent".format(network_space_name)
    else:
        # Find IPs from space
        ips = list(network_space.get_ips())

        # Disable and delete IPs from space
        if not module.check_mode:
            for ip in ips:
                addr = ip["ip_address"]

                # print("Disabling IP {0}".format(addr))
                try:
                    network_space.disable_ip_address(addr)
                except APICommandFailed as err:
                    if err.error_code == "IP_ADDRESS_ALREADY_DISABLED":
                        pass
                        # print("Already disabled IP {0}".format(addr))
                    else:
                        # print("Failed to disable IP {0}".format(addr))
                        module.fail_json(
                            msg="Disabling of network space {0} IP {1} failed".format(
                                network_space_name, addr
                            )
                        )

                # print("Removing IP {0}".format(addr))
                try:
                    network_space.remove_ip_address(addr)
                except Exception as err:
                    module.fail_json(
                        msg="Removal of network space {0} IP {1} failed: {2}".format(
                            network_space_name, addr, err
                        )
                    )

            # Delete space
            network_space.delete()
            changed = True
            msg = "Network space {0} removed".format(network_space_name)
        else:
            changed = False
            msg = "Network space {0} not altered due to checkmode".format(
                network_space_name
            )

    module.exit_json(changed=changed, msg=msg)


def execute_state(module):
    state = module.params["state"]
    try:
        if state == "stat":
            handle_stat(module)
        elif state == "present":
            handle_present(module)
        elif state == "absent":
            handle_absent(module)
        else:
            module.fail_json(
                msg="Internal handler error. Invalid state: {0}".format(state)
            )
    finally:
        system = get_system(module)
        system.logout()


def main():
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(
                default="present", required=False, choices=["stat", "present", "absent"]
            ),
            service=dict(
                default="replication",
                required=False,
                choices=["replication", "NAS_SERVICE", "ISCSI_SERVICE"],
            ),
            mtu=dict(default=None, required=False, type=int),
            network=dict(default=None, required=False),
            netmask=dict(default=None, required=False, type=int),
            default_gateway=dict(default=None, required=False),
            interfaces=dict(default=list(), required=False, type="list", elements="int"),
            network_config=dict(default=dict(), required=False, type=dict),
            ips=dict(default=list(), required=False, type="list", elements="str"),
            rate_limit=dict(default=None, required=False, type=int),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib("infinisdk"))

    execute_state(module)


if __name__ == "__main__":
    main()
