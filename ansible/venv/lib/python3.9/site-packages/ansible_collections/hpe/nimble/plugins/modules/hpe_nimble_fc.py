#!/usr/bin/python

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
description: Manage storage Fibre Channel on an HPE Nimble Storage group.
module: hpe_nimble_fc
options:
  array_name_or_serial:
    required: True
    type: str
    description:
    - Name or serial number of array where the interface is hosted.
  controller:
    required: False
    type: str
    description:
    - Name (A or B) of the controller where the interface is hosted.
  hw_upgrade:
    required: False
    type: bool
    description:
    - Update fibre channel configuration after hardware changes. Possible values:- 'true' 'false'.
  name:
    required: False
    type: str
    description:
    - Name of fibre channel interface
  online:
    required: False
    type: bool
    description:
    - Identify whether the fibre channel interface is online. Possible values:- 'true' 'false'.
  precheck:
    required: False
    type: bool
    description:
    - Check if the interfaces are offline before regenerating the WWNN. Possible values:- 'true' 'false'.
  regenerate:
    required: False
    type: bool
    description:
    - Regenerate fibre channel configuration. Possible values:- 'true' 'false'.
  state:
    required: True
    choices:
    - present
    type: str
    description:
    - The fibre channel operation.
  wwnn_base_str:
    required: False
    type: str
    description:
    - Base WWNN. Six bytes expressed in hex separated by colons. Example:- 'af:32:f1'.
extends_documentation_fragment: hpe.nimble.hpe_nimble
short_description: Manage the HPE Nimble Storage Fibre Channel
version_added: "1.0.0"
notes:
  - This module does not support C(check_mode).
'''

EXAMPLES = r'''

- name: Update fibre channel interface
  hpe.nimble.hpe_nimble_fc:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    array_name_or_serial: "{{ array_name_or_serial | mandatory }}"
    name: "{{ name | mandatory }}"
    controller: "{{ controller | mandatory }}"
    online: "{{ online | mandatory }}"
    state: "{{ 'present' }}"

- name: Regenerate fibre channel config
  hpe.nimble.hpe_nimble_fc:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    array_name_or_serial: "{{ array_name_or_serial | mandatory }}" # provide the group_leader_array name
    wwnn_base_str: "{{ wwnn_base_str | mandatory }}"
    regenerate: true
    precheck: true
    state: "{{ 'present' }}"

- name: Hardware upgrade for fibre channel
  hpe.nimble.hpe_nimble_fc:
    host: "{{ host }}"
    username: "{{ username }}"
    password: "{{ password }}"
    array_name_or_serial: "{{ array_name_or_serial | mandatory }}"
    hw_upgrade: true
    state: "{{ 'present' }}"

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


def update_fc_interface(
        client_obj,
        array_name_or_serial,
        fc_name,
        controller,
        online):

    if utils.is_null_or_empty(array_name_or_serial):
        return (False, False, "Fibre channel interface update failed as no array name is provided.", {}, {})
    if utils.is_null_or_empty(fc_name):
        return (False, False, "Fibre channel interface update failed as no interface name is provided.", {}, {})
    if utils.is_null_or_empty(controller):
        return (False, False, "Fibre channel interface update failed as no controller name is provided.", {}, {})
    if utils.is_null_or_empty(online):
        return (False, False, "Fibre channel interface update failed as online flag is not provided.", {}, {})
    try:
        # get the details of the fc
        fc_resp = client_obj.fibre_channel_interfaces.list(detail=True, array_name_or_serial=array_name_or_serial)
        if fc_resp is None:
            return (False, False, f"No fibre channel is present for array '{array_name_or_serial}'.", {}, {})
        else:
            fc_result = None
            for fc_interface_obj in fc_resp:
                if fc_interface_obj.attrs.get("name") == fc_name and fc_interface_obj.attrs.get("controller_name") == controller:
                    fc_result = fc_interface_obj
                    break
            if fc_result is not None:
                changed_attrs_dict, params = utils.remove_unchanged_or_null_args(fc_result, online=online)
                if changed_attrs_dict.__len__() > 0:
                    fc_result = client_obj.fibre_channel_interfaces.update(id=fc_result.attrs.get("id"), online=online)
                    if hasattr(fc_result, 'attrs'):
                        fc_result = fc_result.attrs
                    return (True, True, "Updated fibre channel interface.", {}, fc_result)
                else:
                    if hasattr(fc_result, 'attrs'):
                        fc_result = fc_result.attrs
                    return (True, False, "Fibre channel interface already in given state.", {}, fc_result)
    except Exception as ex:
        return (False, False, f"Fibre channel update failed |'{ex}'", {}, {})


def regenerate_wwn(
        client_obj,
        array_name_or_serial,
        wwnn_base_str,
        precheck):

    if utils.is_null_or_empty(array_name_or_serial):
        return (False, False, "Fibre channel config update failed as no array name is provided.", {}, {})
    try:
        # get the details of the fc config
        fc_config_resp = client_obj.fibre_channel_configs.get(id=None, group_leader_array=array_name_or_serial)
        if fc_config_resp is None:
            return (False, False, f"No fibre channel config is present for array '{array_name_or_serial}'.", {}, {})
        else:
            changed_attrs_dict = {}
            fc_config_resp = client_obj.fibre_channel_configs.regenerate(fc_config_resp.attrs.get("id"), precheck, wwnn_base_str)
            if hasattr(fc_config_resp, 'attrs'):
                fc_config_resp = fc_config_resp.attrs
            changed_attrs_dict['wwnn_base_str'] = wwnn_base_str
            return (True, True, f"Updated fibre channel config for group leader array '{array_name_or_serial}'."
                    f"Modified the following fields '{changed_attrs_dict}'.", changed_attrs_dict, fc_config_resp)
    except Exception as ex:
        return (False, False, f"Fibre channel config update failed |'{ex}'", {}, {})


def upgrade_hardware(
        client_obj,
        array_name_or_serial):

    if utils.is_null_or_empty(array_name_or_serial):
        return (False, False, "Hardware update failed as no array name is provided.", {}, {})
    try:
        # get the details of the fc config
        fc_config_resp = client_obj.fibre_channel_configs.get(id=None, group_leader_array=array_name_or_serial)
        if fc_config_resp is None:
            return (False, False, f"No fibre channel config is present for array '{array_name_or_serial}'.", {}, {})
        else:
            fc_config_resp = client_obj.fibre_channel_configs.hw_upgrade(fc_config_resp.attrs.get("id"))
            if hasattr(fc_config_resp, 'attrs'):
                fc_config_resp = fc_config_resp.attrs
            return (True, True, f"Hardware update for group leader array '{array_name_or_serial}' done successfully", {}, fc_config_resp)
    except Exception as ex:
        return (False, False, f"Hardware update failed |'{ex}'", {}, {})


def main():

    fields = {
        "array_name_or_serial": {
            "required": True,
            "type": "str"
        },
        "controller": {
            "required": False,
            "type": "str"
        },
        "hw_upgrade": {
            "required": False,
            "type": "bool"
        },
        "name": {
            "required": False,
            "type": "str"
        },
        "online": {
            "required": False,
            "type": "bool"
        },
        "precheck": {
            "required": False,
            "type": "bool"
        },
        "regenerate": {
            "required": False,
            "type": "bool"
        },
        "state": {
            "required": True,
            "choices": ['present'],
            "type": "str"
        },
        "wwnn_base_str": {
            "required": False,
            "type": "str"
        },
    }
    default_fields = utils.basic_auth_arg_fields()
    fields.update(default_fields)
    module = AnsibleModule(argument_spec=fields)
    if client is None:
        module.fail_json(msg='Python nimble-sdk could not be found.')

    hostname = module.params["host"]
    username = module.params["username"]
    password = module.params["password"]
    array_name_or_serial = module.params["array_name_or_serial"]
    controller = module.params["controller"]
    hw_upgrade = module.params["hw_upgrade"]
    fc_name = module.params["name"]
    online = module.params["online"]
    precheck = module.params["precheck"]
    regenerate = module.params["regenerate"]
    state = module.params["state"]
    wwnn_base_str = module.params["wwnn_base_str"]

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
        if state == "present":
            if regenerate is True:
                return_status, changed, msg, changed_attrs_dict, resp = regenerate_wwn(
                    client_obj,
                    array_name_or_serial,
                    wwnn_base_str,
                    precheck)

            elif hw_upgrade is True:
                return_status, changed, msg, changed_attrs_dict, resp = upgrade_hardware(
                    client_obj,
                    array_name_or_serial)

            else:
                return_status, changed, msg, changed_attrs_dict, resp = update_fc_interface(
                    client_obj,
                    array_name_or_serial,
                    fc_name,
                    controller,
                    online)
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
