#!/usr/bin/python

# # Copyright 2020 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# author Alok Ranjan (alok.ranjan2@hpe.com)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = r'''
---
author:
  - HPE Nimble Storage Ansible Team (@ar-india) <nimble-dcs-storage-automation-eng@hpe.com>
description: Manage the storage network configuration on the HPE Nimble Storage group.
module: hpe_nimble_network
options:
  activate:
    required: False
    type: bool
    description:
    - Activate a network configuration.
  array:
    required: False
    type: list
    elements: dict
    description:
    - List of array network configs.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing network config.
  iscsi_automatic_connection_method:
    required: False
    type: bool
    description:
    - Whether automatic connection method is enabled. Enabling this means means redirecting connections from the specified iSCSI
      discovery IP address to the best data IP address based on connection counts.
  iscsi_connection_rebalancing:
    required: False
    type: bool
    description:
    - Whether rebalancing is enabled. Enabling this means rebalancing iSCSI connections by periodically breaking existing
      connections that are out-of-balance, allowing the host to reconnect to a more appropriate data IP address.
  ignore_validation_mask:
    required: False
    type: int
    description:
    - Indicates whether to ignore the validation.
  mgmt_ip:
    required: False
    type: str
    description:
    - Management IP address for the Group. Four numbers in the range (0,255) separated by periods.
  name:
    required: True
    type: str
    choices:
    -  active
    -  backup
    -  draft
    description:
    - Name of the network configuration. Use the name 'draft' when creating a draft configuration.
  secondary_mgmt_ip:
    required: False
    type: str
    description:
    - Secondary management IP address for the Group. Four numbers in the range [0,255] separated by periods.
  subnet:
    required: False
    type: list
    elements: dict
    description:
    - List of subnet configs.
  route:
    required: False
    type: list
    elements: dict
    description:
    - List of static routes.
  state:
    required: True
    choices:
    -  create
    -  present
    -  absent
    type: str
    description:
    - The network config operation.
  validate:
    required: False
    type: bool
    description:
    - Validate a network configuration.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage network configuration
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create, then create network config, fails if it exist or cannot create
# if state is present, then create network config if not present ,else success
- name: Create network config
  hpe.nimble.hpe_nimble_network:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    route: "{{ route }}"
    subnet: "{{ subnet }}"
    array: "{{ array }}"
    iscsi_automatic_connection_method: true
    iscsi_connection_rebalancing: False
    mgmt_ip: "{{ mgmt_ip }}"
    state: "{{ state | default('present') }}"

- name: Delete network config
  hpe.nimble.hpe_nimble_network:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "absent"

- name: Validate network config
  hpe.nimble.hpe_nimble_network:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    ignore_validation_mask: 1
    validate: true

- name: Activate Network config
  hpe.nimble.hpe_nimble_network:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    name: "{{ name }}"
    state: "present"
    ignore_validation_mask: 1
    activate: true

'''
RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
try:
    from nimbleclient.v1 import client
except ImportError:
    client = None
from ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble import __version__ as NIMBLE_ANSIBLE_VERSION
import ansible_collections.hpe.nimble.plugins.module_utils.hpe_nimble as utils


def create_update_network_config(
        client_obj,
        name,
        state,
        iscsi_automatic_connection_method,
        iscsi_connection_rebalancing,
        mgmt_ip,
        change_name,
        **kwargs):

    if utils.is_null_or_empty(name):
        return (False, False, "Create network config failed as name is not present.", {}, {})

    try:
        network_resp = client_obj.network_configs.get(id=None, name=name)
        if utils.is_null_or_empty(network_resp):
            params = utils.remove_null_args(**kwargs)
            network_resp = client_obj.network_configs.create(name=name,
                                                             iscsi_automatic_connection_method=iscsi_automatic_connection_method,
                                                             iscsi_connection_rebalancing=iscsi_connection_rebalancing,
                                                             mgmt_ip=mgmt_ip,
                                                             **params)
            return (True, True, f"Network config '{name}' created successfully.", {}, network_resp.attrs)
        else:
            if state == "create":
                return (False, False, f"Network config '{name}' cannot be created as it is already present in given state.", {}, network_resp.attrs)

            # update case
            kwargs['name'] = change_name
            changed_attrs_dict, params = utils.remove_unchanged_or_null_args(network_resp, **kwargs)
            # even though some of the attributes have not changed but it still has to be passed in case of update.
            params = utils.remove_null_args(**kwargs)
            if changed_attrs_dict.__len__() > 0:
                network_resp = client_obj.network_configs.update(id=network_resp.attrs.get("id"),
                                                                 name=name,
                                                                 iscsi_automatic_connection_method=iscsi_automatic_connection_method,
                                                                 iscsi_connection_rebalancing=iscsi_connection_rebalancing,
                                                                 mgmt_ip=mgmt_ip,
                                                                 **params)
                return (True, True, f"Network config '{name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                        changed_attrs_dict, network_resp.attrs)
            else:
                return (True, False, f"Network config '{network_resp.attrs.get('name')}' already present in given state.", {}, network_resp.attrs)
    except Exception as ex:
        return (False, False, f"Network config creation failed |'{ex}'", {}, {})


def delete_network_config(
        client_obj,
        name):

    if utils.is_null_or_empty(name):
        return (False, False, "Delete network config failed as name is not present.", {})

    try:
        network_resp = client_obj.network_configs.get(id=None, name=name)
        if utils.is_null_or_empty(network_resp):
            return (False, False, f"Network config '{name}' cannot be deleted as it is not present.", {})

        client_obj.network_configs.delete(id=network_resp.attrs.get("id"))
        return (True, True, f"Deleted network config '{name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Delete network config failed |'{ex}'", {})


def validate_network_config(
        client_obj,
        name,
        ignore_validation_mask):

    if utils.is_null_or_empty(name):
        return (False, False, "Validate network config failed as name is not present.", {})

    try:
        network_resp = client_obj.network_configs.get(id=None, name=name)
        if utils.is_null_or_empty(network_resp):
            return (False, False, f"Network config '{name}' cannot be validated as it is not present.", {})

        client_obj.network_configs.validate_netconfig(
            id=network_resp.attrs.get("id"),
            ignore_validation_mask=ignore_validation_mask)

        return (True, False, f"Validated network config '{name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Validate Network config failed |'{ex}'", {})


def activate_network_config(
        client_obj,
        name,
        ignore_validation_mask):

    if utils.is_null_or_empty(name):
        return (False, False, "Activate network config failed as name is not present.", {})

    try:
        network_resp = client_obj.network_configs.get(id=None, name=name)
        if utils.is_null_or_empty(network_resp):
            return (False, False, f"Network config '{name}' cannot be activated as it is not present.", {})

        client_obj.network_configs.activate_netconfig(id=network_resp.attrs.get("id"),
                                                      ignore_validation_mask=ignore_validation_mask)

        return (True, True, f"Activated network config '{name}' successfully.", {})
    except Exception as ex:
        return (False, False, f"Activate Network config failed |'{ex}'", {})


def main():

    fields = {
        "activate": {
            "required": False,
            "type": "bool"
        },
        "array": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "change_name": {
            "required": False,
            "type": "str"
        },
        "iscsi_automatic_connection_method": {
            "required": False,
            "type": "bool"
        },
        "iscsi_connection_rebalancing": {
            "required": False,
            "type": "bool"
        },
        "ignore_validation_mask": {
            "required": False,
            "type": "int"
        },
        "mgmt_ip": {
            "required": False,
            "type": "str"
        },
        "name": {
            "required": True,
            "choices": ['active',
                        'backup',
                        'draft'
                        ],
            "type": "str"
        },
        "secondary_mgmt_ip": {
            "required": False,
            "type": "str"
        },
        "subnet": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "route": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "state": {
            "required": True,
            "choices": ['create',
                        'present',
                        'absent'
                        ],
            "type": "str"
        },
        "validate": {
            "required": False,
            "type": "bool"
        }
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    required_if = [('state', 'create', ['array', 'iscsi_automatic_connection_method', 'iscsi_connection_rebalancing', 'mgmt_ip', 'subnet', 'route'])]
    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    activate = module.params["activate"]
    array = module.params["array"]
    iscsi_automatic_connection_method = module.params["iscsi_automatic_connection_method"]
    iscsi_connection_rebalancing = module.params["iscsi_connection_rebalancing"]
    ignore_validation_mask = module.params["ignore_validation_mask"]
    mgmt_ip = module.params["mgmt_ip"]
    name = module.params["name"]
    change_name = module.params["change_name"]
    secondary_mgmt_ip = module.params["secondary_mgmt_ip"]
    subnet = module.params["subnet"]
    route = module.params["route"]
    state = module.params["state"]
    validate = module.params["validate"]

    if (username is None or password is None or hostname is None):
        module.fail_json(
            msg="Missing variables: hostname, username and password is mandatory.")

    # defaults
    return_status = changed = False
    msg = "No task to run."
    resp = None
    try:
        client_obj = client.NimOSClient(
            hostname,
            username,
            password,
            f"HPE Nimble Ansible Modules v{NIMBLE_ANSIBLE_VERSION}"
        )

        # States
        if ((validate is None or validate is False)
            and (activate is None or activate is False)
                and (state == "create" or state == "present")):
            # if not client_obj.network_configs.get(id=None, name=name) or state == "create":
            return_status, changed, msg, changed_attrs_dict, resp = create_update_network_config(
                client_obj,
                name,
                state,
                iscsi_automatic_connection_method,
                iscsi_connection_rebalancing,
                mgmt_ip,
                change_name,
                array_list=array,
                ignore_validation_mask=ignore_validation_mask,
                secondary_mgmt_ip=secondary_mgmt_ip,
                subnet_list=subnet,
                route_list=route)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_network_config(client_obj, name)

        elif state == "present" and validate is True:
            return_status, changed, msg, changed_attrs_dict = validate_network_config(client_obj, name, ignore_validation_mask)

        elif state == "present" and activate is True:
            return_status, changed, msg, changed_attrs_dict = activate_network_config(client_obj, name, ignore_validation_mask)
    except Exception as ex:
        # failed for some reason.
        msg = str(ex)

    if return_status:
        if utils.is_null_or_empty(resp):
            module.exit_json(return_status=return_status, changed=changed, msg=msg)
        else:
            module.exit_json(return_status=return_status, changed=changed, msg=msg, attrs=resp)
    else:
        module.fail_json(return_status=return_status, changed=changed, msg=msg)


if __name__ == '__main__':
    main()
