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
module: fortios_system_fabric_vpn
short_description: Setup for self orchestrated fabric auto discovery VPN in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and fabric_vpn category.
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

    system_fabric_vpn:
        description:
            - Setup for self orchestrated fabric auto discovery VPN.
        default: null
        type: dict
        suboptions:
            advertised_subnets:
                description:
                    - Local advertised subnets.
                type: list
                elements: dict
                suboptions:
                    access:
                        description:
                            - Access policy direction.
                        type: str
                        choices:
                            - 'inbound'
                            - 'bidirectional'
                    bgp_network:
                        description:
                            - Underlying BGP network. Source router.bgp.network.id.
                        type: int
                    firewall_address:
                        description:
                            - Underlying firewall address. Source firewall.address.name.
                        type: str
                    id:
                        description:
                            - ID.
                        required: true
                        type: int
                    policies:
                        description:
                            - Underlying policies. Source firewall.policy.policyid.
                        type: list
                        elements: int
                    prefix:
                        description:
                            - Network prefix.
                        type: str
            bgp_as:
                description:
                    - BGP Router AS number, valid from 1 to 4294967295.
                type: int
            branch_name:
                description:
                    - Branch name.
                type: str
            health_checks:
                description:
                    - Underlying health checks. Source system.sdwan.health-check.name.
                type: list
                elements: str
            loopback_address_block:
                description:
                    - 'IPv4 address and subnet mask for hub"s loopback address, syntax: X.X.X.X/24.'
                type: str
            loopback_advertised_subnet:
                description:
                    - Loopback advertised subnet reference. Source system.fabric-vpn.advertised-subnets.id.
                type: int
            loopback_interface:
                description:
                    - Loopback interface. Source system.interface.name.
                type: str
            overlays:
                description:
                    - Local overlay interfaces table.
                type: list
                elements: dict
                suboptions:
                    bgp_neighbor:
                        description:
                            - Underlying BGP neighbor entry. Source router.bgp.neighbor.ip.
                        type: str
                    bgp_neighbor_group:
                        description:
                            - Underlying BGP neighbor group entry. Source router.bgp.neighbor-group.name.
                        type: str
                    bgp_neighbor_range:
                        description:
                            - Underlying BGP neighbor range entry. Source router.bgp.neighbor-range.id.
                        type: int
                    bgp_network:
                        description:
                            - Underlying BGP network. Source router.bgp.network.id.
                        type: int
                    interface:
                        description:
                            - Underlying interface name. Source system.interface.name.
                        type: str
                    ipsec_phase1:
                        description:
                            - IPsec interface. Source vpn.ipsec.phase1-interface.name.
                        type: str
                    name:
                        description:
                            - Overlay name.
                        required: true
                        type: str
                    overlay_policy:
                        description:
                            - The overlay policy to allow ADVPN thru traffic. Source firewall.policy.policyid.
                        type: int
                    overlay_tunnel_block:
                        description:
                            - 'IPv4 address and subnet mask for the overlay tunnel , syntax: X.X.X.X/24.'
                        type: str
                    remote_gw:
                        description:
                            - IP address of the hub gateway (Set by hub).
                        type: str
                    route_policy:
                        description:
                            - Underlying router policy. Source router.policy.seq-num.
                        type: int
                    sdwan_member:
                        description:
                            - Reference to SD-WAN member entry. Source system.sdwan.members.seq-num.
                        type: int
            policy_rule:
                description:
                    - Policy creation rule.
                type: str
                choices:
                    - 'health-check'
                    - 'manual'
                    - 'auto'
            psksecret:
                description:
                    - Pre-shared secret for ADVPN.
                type: str
            sdwan_zone:
                description:
                    - Reference to created SD-WAN zone. Source system.sdwan.zone.name.
                type: str
            status:
                description:
                    - Enable/disable Fabric VPN.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            sync_mode:
                description:
                    - Setting synchronised by fabric or manual.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            vpn_role:
                description:
                    - Fabric VPN role.
                type: str
                choices:
                    - 'hub'
                    - 'spoke'
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
  - name: Setup for self orchestrated fabric auto discovery VPN.
    fortios_system_fabric_vpn:
      vdom:  "{{ vdom }}"
      system_fabric_vpn:
        advertised_subnets:
         -
            access: "inbound"
            bgp_network: "0"
            firewall_address: "<your_own_value> (source firewall.address.name)"
            id:  "7"
            policies: "<your_own_value> (source firewall.policy.policyid)"
            prefix: "<your_own_value>"
        bgp_as: "0"
        branch_name: "<your_own_value>"
        health_checks: "<your_own_value> (source system.sdwan.health-check.name)"
        loopback_address_block: "<your_own_value>"
        loopback_advertised_subnet: "0"
        loopback_interface: "<your_own_value> (source system.interface.name)"
        overlays:
         -
            bgp_neighbor: "<your_own_value> (source router.bgp.neighbor.ip)"
            bgp_neighbor_group: "<your_own_value> (source router.bgp.neighbor-group.name)"
            bgp_neighbor_range: "0"
            bgp_network: "0"
            interface: "<your_own_value> (source system.interface.name)"
            ipsec_phase1: "<your_own_value> (source vpn.ipsec.phase1-interface.name)"
            name: "default_name_23"
            overlay_policy: "0"
            overlay_tunnel_block: "<your_own_value>"
            remote_gw: "<your_own_value>"
            route_policy: "0"
            sdwan_member: "0"
        policy_rule: "health-check"
        psksecret: "<your_own_value>"
        sdwan_zone: "<your_own_value> (source system.sdwan.zone.name)"
        status: "enable"
        sync_mode: "enable"
        vpn_role: "hub"

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


def filter_system_fabric_vpn_data(json):
    option_list = [
        "advertised_subnets",
        "bgp_as",
        "branch_name",
        "health_checks",
        "loopback_address_block",
        "loopback_advertised_subnet",
        "loopback_interface",
        "overlays",
        "policy_rule",
        "psksecret",
        "sdwan_zone",
        "status",
        "sync_mode",
        "vpn_role",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def flatten_single_path(data, path, index):
    if (
        not data
        or index == len(path)
        or path[index] not in data
        or not data[path[index]]
    ):
        return

    if index == len(path) - 1:
        data[path[index]] = " ".join(str(elem) for elem in data[path[index]])
    elif isinstance(data[path[index]], list):
        for value in data[path[index]]:
            flatten_single_path(value, path, index + 1)
    else:
        flatten_single_path(data[path[index]], path, index + 1)


def flatten_multilists_attributes(data):
    multilist_attrs = [
        ["advertised_subnets", "policies"],
        ["health_checks"],
    ]

    for attr in multilist_attrs:
        flatten_single_path(data, attr, 0)

    return data


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


def system_fabric_vpn(data, fos):
    vdom = data["vdom"]
    system_fabric_vpn_data = data["system_fabric_vpn"]
    system_fabric_vpn_data = flatten_multilists_attributes(system_fabric_vpn_data)
    filtered_data = underscore_to_hyphen(
        filter_system_fabric_vpn_data(system_fabric_vpn_data)
    )

    return fos.set("system", "fabric-vpn", data=filtered_data, vdom=vdom)


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


def fortios_system(data, fos):

    fos.do_member_operation("system", "fabric-vpn")
    if data["system_fabric_vpn"]:
        resp = system_fabric_vpn(data, fos)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_fabric_vpn"))

    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "revisions": {"v7.4.0": True, "v7.2.4": True},
    "type": "dict",
    "children": {
        "status": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "enable", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "disable", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "sync_mode": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "enable", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "disable", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "branch_name": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
        },
        "policy_rule": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {
                    "value": "health-check",
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                },
                {"value": "manual", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "auto", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "vpn_role": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
            "options": [
                {"value": "hub", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "spoke", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "overlays": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                    "required": True,
                },
                "overlay_tunnel_block": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "remote_gw": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "interface": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "bgp_neighbor": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "overlay_policy": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                },
                "bgp_network": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                },
                "route_policy": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                },
                "bgp_neighbor_group": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "bgp_neighbor_range": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                },
                "ipsec_phase1": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "sdwan_member": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                },
            },
            "revisions": {"v7.4.0": True, "v7.2.4": True},
        },
        "advertised_subnets": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                    "required": True,
                },
                "prefix": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "access": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                    "options": [
                        {
                            "value": "inbound",
                            "revisions": {"v7.4.0": True, "v7.2.4": True},
                        },
                        {
                            "value": "bidirectional",
                            "revisions": {"v7.4.0": True, "v7.2.4": True},
                        },
                    ],
                },
                "bgp_network": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "integer",
                },
                "firewall_address": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "string",
                },
                "policies": {
                    "revisions": {"v7.4.0": True, "v7.2.4": True},
                    "type": "list",
                    "multiple_values": True,
                    "elements": "int",
                },
            },
            "revisions": {"v7.4.0": True, "v7.2.4": True},
        },
        "loopback_address_block": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
        },
        "loopback_interface": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "string",
        },
        "loopback_advertised_subnet": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "integer",
        },
        "psksecret": {"revisions": {"v7.4.0": True, "v7.2.4": True}, "type": "string"},
        "bgp_as": {"revisions": {"v7.4.0": True, "v7.2.4": True}, "type": "integer"},
        "sdwan_zone": {"revisions": {"v7.4.0": True, "v7.2.4": True}, "type": "string"},
        "health_checks": {
            "revisions": {"v7.4.0": True, "v7.2.4": True},
            "type": "list",
            "multiple_values": True,
            "elements": "str",
        },
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = None
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
        "system_fabric_vpn": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_fabric_vpn"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["system_fabric_vpn"]["options"][attribute_name]["required"] = True

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
            fos, versioned_schema, "system_fabric_vpn"
        )

        is_error, has_changed, result, diff = fortios_system(module.params, fos)

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
