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
module: fortios_extender_controller_extender_profile
short_description: FortiExtender extender profile configuration in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify extender_controller feature and extender_profile category.
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
    extender_controller_extender_profile:
        description:
            - FortiExtender extender profile configuration.
        default: null
        type: dict
        suboptions:
            allowaccess:
                description:
                    - Control management access to the managed extender. Separate entries with a space.
                type: list
                elements: str
                choices:
                    - 'ping'
                    - 'telnet'
                    - 'http'
                    - 'https'
                    - 'ssh'
                    - 'snmp'
            bandwidth_limit:
                description:
                    - FortiExtender LAN extension bandwidth limit (Mbps).
                type: int
            cellular:
                description:
                    - FortiExtender cellular configuration.
                type: dict
                suboptions:
                    controller_report:
                        description:
                            - FortiExtender controller report configuration.
                        type: dict
                        suboptions:
                            interval:
                                description:
                                    - Controller report interval.
                                type: int
                            signal_threshold:
                                description:
                                    - Controller report signal threshold.
                                type: int
                            status:
                                description:
                                    - FortiExtender controller report status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                    dataplan:
                        description:
                            - Dataplan names.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Dataplan name. Source extender-controller.dataplan.name.
                                required: true
                                type: str
                    modem1:
                        description:
                            - Configuration options for modem 1.
                        type: dict
                        suboptions:
                            auto_switch:
                                description:
                                    - FortiExtender auto switch configuration.
                                type: dict
                                suboptions:
                                    dataplan:
                                        description:
                                            - Automatically switch based on data usage.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        description:
                                            - Auto switch by disconnect.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect_period:
                                        description:
                                            - Automatically switch based on disconnect period.
                                        type: int
                                    disconnect_threshold:
                                        description:
                                            - Automatically switch based on disconnect threshold.
                                        type: int
                                    signal:
                                        description:
                                            - Automatically switch based on signal strength.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch_back:
                                        description:
                                            - Auto switch with switch back multi-options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'time'
                                            - 'timer'
                                    switch_back_time:
                                        description:
                                            - 'Automatically switch over to preferred SIM/carrier at a specified time in UTC (HH:MM).'
                                        type: str
                                    switch_back_timer:
                                        description:
                                            - Automatically switch over to preferred SIM/carrier after the given time (3600 - 2147483647 sec).
                                        type: int
                            conn_status:
                                description:
                                    - Connection status.
                                type: int
                            default_sim:
                                description:
                                    - Default SIM selection.
                                type: str
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                description:
                                    - FortiExtender GPS enable/disable.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preferred_carrier:
                                description:
                                    - Preferred carrier.
                                type: str
                            redundant_intf:
                                description:
                                    - Redundant interface.
                                type: str
                            redundant_mode:
                                description:
                                    - FortiExtender mode.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin:
                                description:
                                    - SIM #1 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin_code:
                                description:
                                    - SIM #1 PIN password.
                                type: str
                            sim2_pin:
                                description:
                                    - SIM #2 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2_pin_code:
                                description:
                                    - SIM #2 PIN password.
                                type: str
                    modem2:
                        description:
                            - Configuration options for modem 2.
                        type: dict
                        suboptions:
                            auto_switch:
                                description:
                                    - FortiExtender auto switch configuration.
                                type: dict
                                suboptions:
                                    dataplan:
                                        description:
                                            - Automatically switch based on data usage.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect:
                                        description:
                                            - Auto switch by disconnect.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    disconnect_period:
                                        description:
                                            - Automatically switch based on disconnect period.
                                        type: int
                                    disconnect_threshold:
                                        description:
                                            - Automatically switch based on disconnect threshold.
                                        type: int
                                    signal:
                                        description:
                                            - Automatically switch based on signal strength.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                                    switch_back:
                                        description:
                                            - Auto switch with switch back multi-options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'time'
                                            - 'timer'
                                    switch_back_time:
                                        description:
                                            - 'Automatically switch over to preferred SIM/carrier at a specified time in UTC (HH:MM).'
                                        type: str
                                    switch_back_timer:
                                        description:
                                            - Automatically switch over to preferred SIM/carrier after the given time (3600 - 2147483647 sec).
                                        type: int
                            conn_status:
                                description:
                                    - Connection status.
                                type: int
                            default_sim:
                                description:
                                    - Default SIM selection.
                                type: str
                                choices:
                                    - 'sim1'
                                    - 'sim2'
                                    - 'carrier'
                                    - 'cost'
                            gps:
                                description:
                                    - FortiExtender GPS enable/disable.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            preferred_carrier:
                                description:
                                    - Preferred carrier.
                                type: str
                            redundant_intf:
                                description:
                                    - Redundant interface.
                                type: str
                            redundant_mode:
                                description:
                                    - FortiExtender mode.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin:
                                description:
                                    - SIM #1 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim1_pin_code:
                                description:
                                    - SIM #1 PIN password.
                                type: str
                            sim2_pin:
                                description:
                                    - SIM #2 PIN status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
                            sim2_pin_code:
                                description:
                                    - SIM #2 PIN password.
                                type: str
                    sms_notification:
                        description:
                            - FortiExtender cellular SMS notification configuration.
                        type: dict
                        suboptions:
                            alert:
                                description:
                                    - SMS alert list.
                                type: dict
                                suboptions:
                                    data_exhausted:
                                        description:
                                            - Display string when data exhausted.
                                        type: str
                                    fgt_backup_mode_switch:
                                        description:
                                            - Display string when FortiGate backup mode switched.
                                        type: str
                                    low_signal_strength:
                                        description:
                                            - Display string when signal strength is low.
                                        type: str
                                    mode_switch:
                                        description:
                                            - Display string when mode is switched.
                                        type: str
                                    os_image_fallback:
                                        description:
                                            - Display string when falling back to a previous OS image.
                                        type: str
                                    session_disconnect:
                                        description:
                                            - Display string when session disconnected.
                                        type: str
                                    system_reboot:
                                        description:
                                            - Display string when system rebooted.
                                        type: str
                            receiver:
                                description:
                                    - SMS notification receiver list.
                                type: list
                                elements: dict
                                suboptions:
                                    alert:
                                        description:
                                            - Alert multi-options.
                                        type: list
                                        elements: str
                                        choices:
                                            - 'system-reboot'
                                            - 'data-exhausted'
                                            - 'session-disconnect'
                                            - 'low-signal-strength'
                                            - 'mode-switch'
                                            - 'os-image-fallback'
                                            - 'fgt-backup-mode-switch'
                                    name:
                                        description:
                                            - FortiExtender SMS notification receiver name.
                                        required: true
                                        type: str
                                    phone_number:
                                        description:
                                            - 'Receiver phone number. Format: [+][country code][area code][local phone number]. For example, +16501234567.'
                                        type: str
                                    status:
                                        description:
                                            - SMS notification receiver status.
                                        type: str
                                        choices:
                                            - 'disable'
                                            - 'enable'
                            status:
                                description:
                                    - FortiExtender SMS notification status.
                                type: str
                                choices:
                                    - 'disable'
                                    - 'enable'
            enforce_bandwidth:
                description:
                    - Enable/disable enforcement of bandwidth on LAN extension interface.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            extension:
                description:
                    - Extension option.
                type: str
                choices:
                    - 'wan-extension'
                    - 'lan-extension'
            id:
                description:
                    - ID.
                type: int
            lan_extension:
                description:
                    - FortiExtender lan extension configuration.
                type: dict
                suboptions:
                    backhaul:
                        description:
                            - LAN extension backhaul tunnel configuration.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - FortiExtender LAN extension backhaul name.
                                required: true
                                type: str
                            port:
                                description:
                                    - FortiExtender uplink port.
                                type: str
                                choices:
                                    - 'wan'
                                    - 'lte1'
                                    - 'lte2'
                                    - 'port1'
                                    - 'port2'
                                    - 'port3'
                                    - 'port4'
                                    - 'port5'
                                    - 'sfp'
                            role:
                                description:
                                    - FortiExtender uplink port.
                                type: str
                                choices:
                                    - 'primary'
                                    - 'secondary'
                            weight:
                                description:
                                    - WRR weight parameter.
                                type: int
                    backhaul_interface:
                        description:
                            - IPsec phase1 interface. Source system.interface.name.
                        type: str
                    backhaul_ip:
                        description:
                            - IPsec phase1 IPv4/FQDN. Used to specify the external IP/FQDN when the FortiGate unit is behind a NAT device.
                        type: str
                    ipsec_tunnel:
                        description:
                            - IPsec tunnel name.
                        type: str
                    link_loadbalance:
                        description:
                            - LAN extension link load balance strategy.
                        type: str
                        choices:
                            - 'activebackup'
                            - 'loadbalance'
            login_password:
                description:
                    - Set the managed extender"s administrator password.
                type: str
            login_password_change:
                description:
                    - Change or reset the administrator password of a managed extender (yes, default, or no).
                type: str
                choices:
                    - 'yes'
                    - 'default'
                    - 'no'
            model:
                description:
                    - Model.
                type: str
                choices:
                    - 'FX201E'
                    - 'FX211E'
                    - 'FX200F'
                    - 'FXA11F'
                    - 'FXE11F'
                    - 'FXA21F'
                    - 'FXE21F'
                    - 'FXA22F'
                    - 'FXE22F'
                    - 'FX212F'
                    - 'FX311F'
                    - 'FX312F'
                    - 'FX511F'
                    - 'FVG21F'
                    - 'FVA21F'
                    - 'FVG22F'
                    - 'FVA22F'
                    - 'FX04DA'
                    - 'FX04DN'
                    - 'FX04DI'
            name:
                description:
                    - FortiExtender profile name.
                required: true
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
  - name: FortiExtender extender profile configuration.
    fortios_extender_controller_extender_profile:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      extender_controller_extender_profile:
        allowaccess: "ping"
        bandwidth_limit: "1024"
        cellular:
            controller_report:
                interval: "300"
                signal_threshold: "10"
                status: "disable"
            dataplan:
             -
                name: "default_name_11 (source extender-controller.dataplan.name)"
            modem1:
                auto_switch:
                    dataplan: "disable"
                    disconnect: "disable"
                    disconnect_period: "600"
                    disconnect_threshold: "3"
                    signal: "disable"
                    switch_back: "time"
                    switch_back_time: "<your_own_value>"
                    switch_back_timer: "86400"
                conn_status: "0"
                default_sim: "sim1"
                gps: "disable"
                preferred_carrier: "<your_own_value>"
                redundant_intf: "<your_own_value>"
                redundant_mode: "disable"
                sim1_pin: "disable"
                sim1_pin_code: "<your_own_value>"
                sim2_pin: "disable"
                sim2_pin_code: "<your_own_value>"
            modem2:
                auto_switch:
                    dataplan: "disable"
                    disconnect: "disable"
                    disconnect_period: "600"
                    disconnect_threshold: "3"
                    signal: "disable"
                    switch_back: "time"
                    switch_back_time: "<your_own_value>"
                    switch_back_timer: "86400"
                conn_status: "0"
                default_sim: "sim1"
                gps: "disable"
                preferred_carrier: "<your_own_value>"
                redundant_intf: "<your_own_value>"
                redundant_mode: "disable"
                sim1_pin: "disable"
                sim1_pin_code: "<your_own_value>"
                sim2_pin: "disable"
                sim2_pin_code: "<your_own_value>"
            sms_notification:
                alert:
                    data_exhausted: "<your_own_value>"
                    fgt_backup_mode_switch: "<your_own_value>"
                    low_signal_strength: "<your_own_value>"
                    mode_switch: "<your_own_value>"
                    os_image_fallback: "<your_own_value>"
                    session_disconnect: "<your_own_value>"
                    system_reboot: "<your_own_value>"
                receiver:
                 -
                    alert: "system-reboot"
                    name: "default_name_63"
                    phone_number: "<your_own_value>"
                    status: "disable"
                status: "disable"
        enforce_bandwidth: "enable"
        extension: "wan-extension"
        id:  "69"
        lan_extension:
            backhaul:
             -
                name: "default_name_72"
                port: "wan"
                role: "primary"
                weight: "1"
            backhaul_interface: "<your_own_value> (source system.interface.name)"
            backhaul_ip: "<your_own_value>"
            ipsec_tunnel: "<your_own_value>"
            link_loadbalance: "activebackup"
        login_password: "<your_own_value>"
        login_password_change: "yes"
        model: "FX201E"
        name: "default_name_83"

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


def filter_extender_controller_extender_profile_data(json):
    option_list = [
        "allowaccess",
        "bandwidth_limit",
        "cellular",
        "enforce_bandwidth",
        "extension",
        "id",
        "lan_extension",
        "login_password",
        "login_password_change",
        "model",
        "name",
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
        ["allowaccess"],
        ["cellular", "sms_notification", "receiver", "alert"],
        ["cellular", "modem1", "auto_switch", "switch_back"],
        ["cellular", "modem2", "auto_switch", "switch_back"],
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


def extender_controller_extender_profile(data, fos):
    vdom = data["vdom"]

    state = data["state"]

    extender_controller_extender_profile_data = data[
        "extender_controller_extender_profile"
    ]
    extender_controller_extender_profile_data = flatten_multilists_attributes(
        extender_controller_extender_profile_data
    )
    filtered_data = underscore_to_hyphen(
        filter_extender_controller_extender_profile_data(
            extender_controller_extender_profile_data
        )
    )

    if state == "present" or state is True:
        return fos.set(
            "extender-controller", "extender-profile", data=filtered_data, vdom=vdom
        )

    elif state == "absent":
        return fos.delete(
            "extender-controller",
            "extender-profile",
            mkey=filtered_data["name"],
            vdom=vdom,
        )
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


def fortios_extender_controller(data, fos):

    fos.do_member_operation("extender-controller", "extender-profile")
    if data["extender_controller_extender_profile"]:
        resp = extender_controller_extender_profile(data, fos)
    else:
        fos._module.fail_json(
            msg="missing task body: %s" % ("extender_controller_extender_profile")
        )

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
        "name": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "string",
            "required": True,
        },
        "id": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "integer",
        },
        "model": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "FX201E",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX211E",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX200F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FXA11F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FXE11F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FXA21F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FXE21F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FXA22F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FXE22F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX212F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX311F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX312F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX511F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FVG21F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FVA21F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FVG22F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FVA22F",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX04DA",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "FX04DN",
                    "revisions": {
                        "v7.0.8": True,
                        "v7.0.7": False,
                        "v7.0.6": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v7.0.3": False,
                        "v7.0.2": False,
                    },
                },
                {
                    "value": "FX04DI",
                    "revisions": {
                        "v7.0.8": True,
                        "v7.0.7": False,
                        "v7.0.6": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v7.0.3": False,
                        "v7.0.2": False,
                    },
                },
            ],
        },
        "extension": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "wan-extension",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "lan-extension",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
            ],
        },
        "allowaccess": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "list",
            "options": [
                {
                    "value": "ping",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "telnet",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "http",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "https",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "ssh",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "snmp",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "login_password_change": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "yes",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "default",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "no",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
            ],
        },
        "login_password": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "string",
        },
        "enforce_bandwidth": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
            ],
        },
        "bandwidth_limit": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "integer",
        },
        "cellular": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "dict",
            "children": {
                "dataplan": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
                "controller_report": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "dict",
                    "children": {
                        "status": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "interval": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "integer",
                        },
                        "signal_threshold": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "integer",
                        },
                    },
                },
                "sms_notification": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "dict",
                    "children": {
                        "status": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "alert": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "dict",
                            "children": {
                                "system_reboot": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "data_exhausted": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "session_disconnect": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "low_signal_strength": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "os_image_fallback": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "mode_switch": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "fgt_backup_mode_switch": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                            },
                        },
                        "receiver": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "name": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "required": True,
                                },
                                "status": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "phone_number": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "alert": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "list",
                                    "options": [
                                        {
                                            "value": "system-reboot",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "data-exhausted",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "session-disconnect",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "low-signal-strength",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "mode-switch",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "os-image-fallback",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "fgt-backup-mode-switch",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                    "multiple_values": True,
                                    "elements": "str",
                                },
                            },
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                        },
                    },
                },
                "modem1": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "dict",
                    "children": {
                        "redundant_mode": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "redundant_intf": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "conn_status": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "integer",
                        },
                        "default_sim": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "sim1",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "sim2",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "carrier",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "cost",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "gps": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "sim1_pin": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "sim2_pin": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "sim1_pin_code": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "sim2_pin_code": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "preferred_carrier": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "auto_switch": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "dict",
                            "children": {
                                "disconnect": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "disconnect_threshold": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "integer",
                                },
                                "disconnect_period": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "integer",
                                },
                                "signal": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "dataplan": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "switch_back": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "list",
                                    "options": [
                                        {
                                            "value": "time",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "timer",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                    "multiple_values": True,
                                    "elements": "str",
                                },
                                "switch_back_time": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "switch_back_timer": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "integer",
                                },
                            },
                        },
                    },
                },
                "modem2": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "dict",
                    "children": {
                        "redundant_mode": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "redundant_intf": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "conn_status": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "integer",
                        },
                        "default_sim": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "sim1",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "sim2",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "carrier",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "cost",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "gps": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "sim1_pin": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "sim2_pin": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "disable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "enable",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "sim1_pin_code": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "sim2_pin_code": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "preferred_carrier": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                        },
                        "auto_switch": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "dict",
                            "children": {
                                "disconnect": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "disconnect_threshold": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "integer",
                                },
                                "disconnect_period": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "integer",
                                },
                                "signal": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "dataplan": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "disable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "enable",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                },
                                "switch_back": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "list",
                                    "options": [
                                        {
                                            "value": "time",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                        {
                                            "value": "timer",
                                            "revisions": {
                                                "v7.2.0": True,
                                                "v7.0.8": True,
                                                "v7.0.7": True,
                                                "v7.0.6": True,
                                                "v7.0.5": True,
                                                "v7.0.4": True,
                                                "v7.0.3": True,
                                                "v7.0.2": True,
                                            },
                                        },
                                    ],
                                    "multiple_values": True,
                                    "elements": "str",
                                },
                                "switch_back_time": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "string",
                                },
                                "switch_back_timer": {
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                    "type": "integer",
                                },
                            },
                        },
                    },
                },
            },
        },
        "lan_extension": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
            },
            "type": "dict",
            "children": {
                "link_loadbalance": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "activebackup",
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                        },
                        {
                            "value": "loadbalance",
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                        },
                    ],
                },
                "ipsec_tunnel": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "string",
                },
                "backhaul_interface": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "string",
                },
                "backhaul_ip": {
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "string",
                },
                "backhaul": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "required": True,
                        },
                        "port": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "wan",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "lte1",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "lte2",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "port1",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "port2",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "port3",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "port4",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "port5",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "sfp",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "role": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "string",
                            "options": [
                                {
                                    "value": "primary",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                                {
                                    "value": "secondary",
                                    "revisions": {
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                    },
                                },
                            ],
                        },
                        "weight": {
                            "revisions": {
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                            },
                            "type": "integer",
                        },
                    },
                    "revisions": {
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                },
            },
        },
    },
    "revisions": {
        "v7.2.0": True,
        "v7.0.8": True,
        "v7.0.7": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v7.0.3": True,
        "v7.0.2": True,
    },
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
        "extender_controller_extender_profile": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["extender_controller_extender_profile"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["extender_controller_extender_profile"]["options"][attribute_name][
                "required"
            ] = True

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
            fos, versioned_schema, "extender_controller_extender_profile"
        )

        is_error, has_changed, result, diff = fortios_extender_controller(
            module.params, fos
        )

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
