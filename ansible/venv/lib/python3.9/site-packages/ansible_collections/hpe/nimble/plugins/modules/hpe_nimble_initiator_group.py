#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2020 Hewlett Packard Enterprise Development LP
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
description: Manage the HPE Nimble Storage initiator groups.
module: hpe_nimble_initiator_group
options:
  access_protocol:
    choices:
    - iscsi
    - fc
    required: False
    type: str
    description:
    - Initiator group access protocol.
  app_uuid:
    required: False
    type: str
    description:
    - Application identifier of initiator group. String of up to 255 alphanumeric characters, hyphen, colon, dot and underscore are allowed.
  change_name:
    required: False
    type: str
    description:
    - Change name of the existing initiator group.
  description:
    required: False
    type: str
    description:
    - Text description of initiator group.
  fc_initiators:
    required: False
    type: list
    elements: dict
    description:
    - List of FC initiators. When create/update fc_initiators, WWPN is required.
  fc_tdz_ports:
    required: False
    type: list
    elements: int
    description:
    - List of target fibre channel ports with target driven zoning configured on this initiator group.
  host_type:
    required: False
    type: str
    description:
    - Initiator group host type. Available options are auto and hpux. The default option is auto. This attribute will be
      applied to all the initiators in the initiator group. Initiators with different host OSes should not be kept in the
      same initiator group having a non-default host type attribute.
  iscsi_initiators:
    required: False
    type: list
    elements: dict
    description:
    - List of iSCSI initiators. When create/update iscsi_initiators, either iqn or ip_address is always required with label.
  metadata:
    required: False
    type: dict
    description:
    - Key-value pairs that augment an initiator group's attributes. List of key-value pairs. Keys must be unique and non-empty.
  name:
    required: True
    type: str
    description:
    - Name of the initiator group.
  state:
    required: True
    choices:
    - present
    - absent
    - create
    type: str
    description:
    - The initiator group operation.
  target_subnets:
    required: False
    type: list
    elements: dict
    description:
    - List of target subnet labels. If specified, discovery and access to volumes will be restricted to the specified subnets.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage initiator groups
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

# if state is create, then create ig. Fails if already present.
# if state is present, then create ig if not present. Succeeds if it already exists.
- name: Create an igroup
  hpe.nimble.hpe_nimble_initiator_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    access_protocol: "{{ access_protocol | default('iscsi')}}"
    name: "{{ name }}"
    iscsi_initiators: "{{ iscsi_initiators | default([])}}"  # list of dictionaries. Each entry in the dictionary has one initiator details.
    description: "{{ description | default(None) }}"
    state: "{{ state | default('present') }}"

- name: Delete igroup
  hpe.nimble.hpe_nimble_initiator_group:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    access_protocol: "{{ access_protocol | default('iscsi')}}"
    name: "{{ name }}"
    state: absent

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


def create_igroup(
        client_obj,
        initiator_group_name,
        **kwargs):

    if utils.is_null_or_empty(initiator_group_name):
        return (False, False, "Initiator group creation failed. Initiator group name is null.", {}, {})

    try:
        ig_resp = client_obj.initiator_groups.get(id=None, name=initiator_group_name)
        if utils.is_null_or_empty(ig_resp):
            # remove unchanged and null arguments from kwargs
            params = utils.remove_null_args(**kwargs)
            ig_resp = client_obj.initiator_groups.create(name=initiator_group_name, **params)
            return (True, True, f"Created initiator Group '{initiator_group_name}' successfully.", {}, ig_resp.attrs)
        else:
            return (False, False, f"Cannot create initiator Group '{initiator_group_name}' as it is already present in given state.", {}, {})

    except Exception as ex:
        return (False, False, f"Initiator group creation failed | {ex}", {}, {})


def update_igroup(
        client_obj,
        ig_resp,
        **kwargs):

    if utils.is_null_or_empty(ig_resp):
        return (False, False, "Update initiator group failed as it is not present.", {}, {})
    try:
        ig_name = ig_resp.attrs.get("name")
        changed_attrs_dict, params = utils.remove_unchanged_or_null_args(ig_resp, **kwargs)
        if changed_attrs_dict.__len__() > 0:
            ig_resp = client_obj.initiator_groups.update(id=ig_resp.attrs.get("id"), **params)
            return (True, True, f"Initiator group '{ig_name}' already present. Modified the following attributes '{changed_attrs_dict}'",
                    changed_attrs_dict, ig_resp.attrs)
        else:
            return (True, False, f"Initiator group '{ig_name}' already present in given state.", {}, ig_resp.attrs)
    except Exception as ex:
        return (False, False, f"Initiator group update failed | {ex}", {}, {})


def delete_igroup(
        client_obj,
        initiator_group_name):

    if utils.is_null_or_empty(initiator_group_name):
        return (False, False, "Initiator group deletion failed as it is not present.", {})

    try:
        # see if the igroup is already present
        ig_resp = client_obj.initiator_groups.get(id=None, name=initiator_group_name)
        if ig_resp is not None:
            client_obj.initiator_groups.delete(ig_resp.attrs.get("id"))
            return (True, True, f"Successfully deleted initiator group '{initiator_group_name}'.", {})
        elif ig_resp is None:
            return (False, False, f"Initiator group '{initiator_group_name}' is not present on array.", {})
        else:
            return (False, False, f"Failed to delete initiator group '{initiator_group_name}'.", {})
    except Exception as ex:
        return (False, False, f"Initiator group deletion failed | {ex}", {})


def main():

    fields = {
        "state": {
            "required": True,
            "choices": ['present',
                        'absent',
                        'create'
                        ],
            "type": "str"
        },
        "change_name": {
            "required": False,
            "type": "str"
        },
        "name": {
            "required": True,
            "type": "str"
        },
        "description": {
            "required": False,
            "type": "str"
        },
        "access_protocol": {
            "choices": ['iscsi',
                        'fc'
                        ],
            "required": False,
            "type": "str"
        },
        "host_type": {
            "required": False,
            "type": "str"
        },
        "fc_tdz_ports": {
            "required": False,
            "type": "list",
            "elements": 'int'
        },
        "target_subnets": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "iscsi_initiators": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "fc_initiators": {
            "required": False,
            "type": "list",
            "elements": 'dict'
        },
        "app_uuid": {
            "required": False,
            "type": "str"
        },
        "metadata": {
            "required": False,
            "type": "dict"
        }
    }

    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    required_if = [('state', 'create', ['access_protocol'])]
    module = AnsibleModule(argument_spec=fields, required_if=required_if)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    state = module.params["state"]
    initiator_group_name = module.params["name"]
    change_name = module.params["change_name"]
    description = module.params["description"]
    access_protocol = module.params["access_protocol"]
    host_type = module.params["host_type"]
    fc_tdz_ports = module.params["fc_tdz_ports"]
    target_subnets = module.params["target_subnets"]
    iscsi_initiators = module.params["iscsi_initiators"]
    fc_initiators = module.params["fc_initiators"]
    app_uuid = module.params["app_uuid"]
    metadata = module.params["metadata"]

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
        if state == "create" or state == "present":
            ig_resp = client_obj.initiator_groups.get(id=None, name=initiator_group_name)
            if utils.is_null_or_empty(ig_resp) or state == "create":

                return_status, changed, msg, changed_attrs_dict, resp = create_igroup(
                    client_obj,
                    initiator_group_name,
                    description=description,
                    access_protocol=access_protocol,
                    host_type=host_type,
                    fc_tdz_ports=fc_tdz_ports,
                    target_subnets=target_subnets,
                    iscsi_initiators=iscsi_initiators,
                    fc_initiators=fc_initiators,
                    app_uuid=app_uuid,
                    metadata=metadata)
            else:
                return_status, changed, msg, changed_attrs_dict, resp = update_igroup(
                    client_obj,
                    ig_resp,
                    name=change_name,
                    description=description,
                    host_type=host_type,
                    fc_tdz_ports=fc_tdz_ports,
                    target_subnets=target_subnets,
                    iscsi_initiators=iscsi_initiators,
                    fc_initiators=fc_initiators,
                    metadata=metadata)

        elif state == "absent":
            return_status, changed, msg, changed_attrs_dict = delete_igroup(client_obj, initiator_group_name)
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
