#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_vpn_kmip_server
short_description: KMIP server entry configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify vpn feature and kmip_server category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

requirements:
    - ansible>=2.9
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    vpn_kmip_server:
        description:
            - KMIP server entry configuration.
        default: null
        type: dict
        suboptions:
            interface:
                description:
                    - Specify outgoing interface to reach server. Source system.interface.name.
                type: str
            interface_select_method:
                description:
                    - Specify how to select outgoing interface to reach server.
                type: str
                choices:
                    - 'auto'
                    - 'sdwan'
                    - 'specify'
            name:
                description:
                    - KMIP server entry name.
                required: true
                type: str
            password:
                description:
                    - Password to use for connectivity to the KMIP server.
                type: str
            server_identity_check:
                description:
                    - Enable/disable KMIP server identity check (verify server FQDN/IP address against the server certificate).
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            server_list:
                description:
                    - KMIP server list.
                type: list
                elements: dict
                suboptions:
                    cert:
                        description:
                            - Client certificate to use for connectivity to the KMIP server. Source vpn.certificate.local.name.
                        type: str
                    id:
                        description:
                            - ID
                        required: true
                        type: int
                    port:
                        description:
                            - KMIP server port.
                        type: int
                    server:
                        description:
                            - KMIP server FQDN or IP address.
                        type: str
                    status:
                        description:
                            - Enable/disable KMIP server.
                        type: str
                        choices:
                            - 'enable'
                            - 'disable'
            source_ip:
                description:
                    - FortiGate IP address to be used for communication with the KMIP server.
                type: str
            ssl_min_proto_version:
                description:
                    - Minimum supported protocol version for SSL/TLS connections .
                type: str
                choices:
                    - 'default'
                    - 'SSLv3'
                    - 'TLSv1'
                    - 'TLSv1-1'
                    - 'TLSv1-2'
            username:
                description:
                    - User name to use for connectivity to the KMIP server.
                type: str
"""

EXAMPLES = """
- hosts: fortigates
  collections:
    - fortinet.fortios
  connection: httpapi
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: KMIP server entry configuration.
    fortios_vpn_kmip_server:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      vpn_kmip_server:
        interface: "<your_own_value> (source system.interface.name)"
        interface_select_method: "auto"
        name: "default_name_5"
        password: "<your_own_value>"
        server_identity_check: "enable"
        server_list:
         -
            cert: "<your_own_value> (source vpn.certificate.local.name)"
            id:  "10"
            port: "5696"
            server: "192.168.100.40"
            status: "enable"
        source_ip: "84.230.14.43"
        ssl_min_proto_version: "default"
        username: "<your_own_value>"

"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)


def filter_vpn_kmip_server_data(json):
    option_list = [
        "interface",
        "interface_select_method",
        "name",
        "password",
        "server_identity_check",
        "server_list",
        "source_ip",
        "ssl_min_proto_version",
        "username",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def vpn_kmip_server(data, fos):
    vdom = data["vdom"]

    state = data["state"]

    vpn_kmip_server_data = data["vpn_kmip_server"]
    filtered_data = underscore_to_hyphen(
        filter_vpn_kmip_server_data(vpn_kmip_server_data)
    )

    if state == "present" or state is True:
        return fos.set("vpn", "kmip-server", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("vpn", "kmip-server", mkey=filtered_data["name"], vdom=vdom)
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_vpn(data, fos):

    fos.do_member_operation("vpn", "kmip-server")
    if data["vpn_kmip_server"]:
        resp = vpn_kmip_server(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("vpn_kmip_server"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {"revisions": {"v7.4.0": True}, "type": "string", "required": True},
        "server_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {"v7.4.0": True},
                    "type": "integer",
                    "required": True,
                },
                "status": {
                    "revisions": {"v7.4.0": True},
                    "type": "string",
                    "options": [
                        {"value": "enable", "revisions": {"v7.4.0": True}},
                        {"value": "disable", "revisions": {"v7.4.0": True}},
                    ],
                },
                "server": {"revisions": {"v7.4.0": True}, "type": "string"},
                "port": {"revisions": {"v7.4.0": True}, "type": "integer"},
                "cert": {"revisions": {"v7.4.0": True}, "type": "string"},
            },
            "revisions": {"v7.4.0": True},
        },
        "username": {"revisions": {"v7.4.0": True}, "type": "string"},
        "password": {"revisions": {"v7.4.0": True}, "type": "string"},
        "ssl_min_proto_version": {
            "revisions": {"v7.4.0": True},
            "type": "string",
            "options": [
                {"value": "default", "revisions": {"v7.4.0": True}},
                {"value": "SSLv3", "revisions": {"v7.4.0": True}},
                {"value": "TLSv1", "revisions": {"v7.4.0": True}},
                {"value": "TLSv1-1", "revisions": {"v7.4.0": True}},
                {"value": "TLSv1-2", "revisions": {"v7.4.0": True}},
            ],
        },
        "server_identity_check": {
            "revisions": {"v7.4.0": True},
            "type": "string",
            "options": [
                {"value": "enable", "revisions": {"v7.4.0": True}},
                {"value": "disable", "revisions": {"v7.4.0": True}},
            ],
        },
        "interface_select_method": {
            "revisions": {"v7.4.0": True},
            "type": "string",
            "options": [
                {"value": "auto", "revisions": {"v7.4.0": True}},
                {"value": "sdwan", "revisions": {"v7.4.0": True}},
                {"value": "specify", "revisions": {"v7.4.0": True}},
            ],
        },
        "interface": {"revisions": {"v7.4.0": True}, "type": "string"},
        "source_ip": {"revisions": {"v7.4.0": True}, "type": "string"},
    },
    "revisions": {"v7.4.0": True},
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "vpn_kmip_server": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["vpn_kmip_server"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["vpn_kmip_server"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=False)
    check_legacy_fortiosapi(module)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_option("enable_log", module.params["enable_log"])
        else:
            connection.set_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "vpn_kmip_server"
        )

        is_error, has_changed, result, diff = fortios_vpn(module.params, fos)

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
