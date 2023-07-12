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
module: fortios_application_list
short_description: Configure application control lists in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify application feature and list category.
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
    application_list:
        description:
            - Configure application control lists.
        default: null
        type: dict
        suboptions:
            app_replacemsg:
                description:
                    - Enable/disable replacement messages for blocked applications.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                description:
                    - Comments.
                type: str
            control_default_network_services:
                description:
                    - Enable/disable enforcement of protocols over selected ports.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            deep_app_inspection:
                description:
                    - Enable/disable deep application inspection.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            default_network_services:
                description:
                    - Default network service entries.
                type: list
                elements: dict
                suboptions:
                    id:
                        description:
                            - Entry ID.
                        required: true
                        type: int
                    port:
                        description:
                            - Port number.
                        type: int
                    services:
                        description:
                            - Network protocols.
                        type: list
                        elements: str
                        choices:
                            - 'http'
                            - 'ssh'
                            - 'telnet'
                            - 'ftp'
                            - 'dns'
                            - 'smtp'
                            - 'pop3'
                            - 'imap'
                            - 'snmp'
                            - 'nntp'
                            - 'https'
                    violation_action:
                        description:
                            - Action for protocols not in the allowlist for selected port.
                        type: str
                        choices:
                            - 'pass'
                            - 'monitor'
                            - 'block'
            enforce_default_app_port:
                description:
                    - Enable/disable default application port enforcement for allowed applications.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            entries:
                description:
                    - Application list entries.
                type: list
                elements: dict
                suboptions:
                    action:
                        description:
                            - Pass or block traffic, or reset connection for traffic from this application.
                        type: str
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                    application:
                        description:
                            - ID of allowed applications.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application IDs.
                                required: true
                                type: int
                    behavior:
                        description:
                            - Application behavior filter.
                        type: list
                        elements: str
                    category:
                        description:
                            - Category ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application category ID.
                                required: true
                                type: int
                    exclusion:
                        description:
                            - ID of excluded applications.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Excluded application IDs.
                                required: true
                                type: int
                    id:
                        description:
                            - Entry ID.
                        required: true
                        type: int
                    log:
                        description:
                            - Enable/disable logging for this application list.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    log_packet:
                        description:
                            - Enable/disable packet logging.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    parameters:
                        description:
                            - Application parameters.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Parameter tuple ID.
                                required: true
                                type: int
                            members:
                                description:
                                    - Parameter tuple members.
                                type: list
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - Parameter.
                                        required: true
                                        type: int
                                    name:
                                        description:
                                            - Parameter name.
                                        type: str
                                    value:
                                        description:
                                            - Parameter value.
                                        type: str
                            value:
                                description:
                                    - Parameter value.
                                type: str
                    per_ip_shaper:
                        description:
                            - Per-IP traffic shaper. Source firewall.shaper.per-ip-shaper.name.
                        type: str
                    popularity:
                        description:
                            - Application popularity filter (1 - 5, from least to most popular).
                        type: list
                        elements: str
                        choices:
                            - '1'
                            - '2'
                            - '3'
                            - '4'
                            - '5'
                    protocols:
                        description:
                            - Application protocol filter.
                        type: list
                        elements: str
                    quarantine:
                        description:
                            - Quarantine method.
                        type: str
                        choices:
                            - 'none'
                            - 'attacker'
                    quarantine_expiry:
                        description:
                            - Duration of quarantine. (Format ###d##h##m, minimum 1m, maximum 364d23h59m). Requires quarantine set to attacker.
                        type: str
                    quarantine_log:
                        description:
                            - Enable/disable quarantine logging.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    rate_count:
                        description:
                            - Count of the rate.
                        type: int
                    rate_duration:
                        description:
                            - Duration (sec) of the rate.
                        type: int
                    rate_mode:
                        description:
                            - Rate limit mode.
                        type: str
                        choices:
                            - 'periodical'
                            - 'continuous'
                    rate_track:
                        description:
                            - Track the packet protocol field.
                        type: str
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                            - 'dhcp-client-mac'
                            - 'dns-domain'
                    risk:
                        description:
                            - Risk, or impact, of allowing traffic from this application to occur (1 - 5; Low, Elevated, Medium, High, and Critical).
                        type: list
                        elements: dict
                        suboptions:
                            level:
                                description:
                                    - Risk, or impact, of allowing traffic from this application to occur (1 - 5; Low, Elevated, Medium, High, and Critical).
                                required: true
                                type: int
                    session_ttl:
                        description:
                            - Session TTL (0 = default).
                        type: int
                    shaper:
                        description:
                            - Traffic shaper. Source firewall.shaper.traffic-shaper.name.
                        type: str
                    shaper_reverse:
                        description:
                            - Reverse traffic shaper. Source firewall.shaper.traffic-shaper.name.
                        type: str
                    sub_category:
                        description:
                            - Application Sub-category ID list.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                description:
                                    - Application sub-category ID.
                                required: true
                                type: int
                    technology:
                        description:
                            - Application technology filter.
                        type: list
                        elements: str
                    vendor:
                        description:
                            - Application vendor filter.
                        type: list
                        elements: str
            extended_log:
                description:
                    - Enable/disable extended logging.
                type: str
                choices:
                    - 'enable'
                    - 'disable'
            force_inclusion_ssl_di_sigs:
                description:
                    - Enable/disable forced inclusion of SSL deep inspection signatures.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            name:
                description:
                    - List name.
                required: true
                type: str
            options:
                description:
                    - Basic application protocol signatures allowed by default.
                type: list
                elements: str
                choices:
                    - 'allow-dns'
                    - 'allow-icmp'
                    - 'allow-http'
                    - 'allow-ssl'
                    - 'allow-quic'
            other_application_action:
                description:
                    - Action for other applications.
                type: str
                choices:
                    - 'pass'
                    - 'block'
            other_application_log:
                description:
                    - Enable/disable logging for other applications.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            p2p_black_list:
                description:
                    - P2P applications to be black listed.
                type: list
                elements: str
                choices:
                    - 'skype'
                    - 'edonkey'
                    - 'bittorrent'
            p2p_block_list:
                description:
                    - P2P applications to be block listed.
                type: list
                elements: str
                choices:
                    - 'skype'
                    - 'edonkey'
                    - 'bittorrent'
            replacemsg_group:
                description:
                    - Replacement message group. Source system.replacemsg-group.name.
                type: str
            unknown_application_action:
                description:
                    - Pass or block traffic from unknown applications.
                type: str
                choices:
                    - 'pass'
                    - 'block'
            unknown_application_log:
                description:
                    - Enable/disable logging for unknown applications.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
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
  - name: Configure application control lists.
    fortios_application_list:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      application_list:
        app_replacemsg: "disable"
        comment: "Comments."
        control_default_network_services: "disable"
        deep_app_inspection: "disable"
        default_network_services:
         -
            id:  "8"
            port: "0"
            services: "http"
            violation_action: "pass"
        enforce_default_app_port: "disable"
        entries:
         -
            action: "pass"
            application:
             -
                id:  "16"
            behavior: "<your_own_value>"
            category:
             -
                id:  "19"
            exclusion:
             -
                id:  "21"
            id:  "22"
            log: "disable"
            log_packet: "disable"
            parameters:
             -
                id:  "26"
                members:
                 -
                    id:  "28"
                    name: "default_name_29"
                    value: "<your_own_value>"
                value: "<your_own_value>"
            per_ip_shaper: "<your_own_value> (source firewall.shaper.per-ip-shaper.name)"
            popularity: "1"
            protocols: "<your_own_value>"
            quarantine: "none"
            quarantine_expiry: "<your_own_value>"
            quarantine_log: "disable"
            rate_count: "0"
            rate_duration: "60"
            rate_mode: "periodical"
            rate_track: "none"
            risk:
             -
                level: "0"
            session_ttl: "0"
            shaper: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
            shaper_reverse: "<your_own_value> (source firewall.shaper.traffic-shaper.name)"
            sub_category:
             -
                id:  "48"
            technology: "<your_own_value>"
            vendor: "<your_own_value>"
        extended_log: "enable"
        force_inclusion_ssl_di_sigs: "disable"
        name: "default_name_53"
        options: "allow-dns"
        other_application_action: "pass"
        other_application_log: "disable"
        p2p_black_list: "skype"
        p2p_block_list: "skype"
        replacemsg_group: "<your_own_value> (source system.replacemsg-group.name)"
        unknown_application_action: "pass"
        unknown_application_log: "disable"

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
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)


def filter_application_list_data(json):
    option_list = [
        "app_replacemsg",
        "comment",
        "control_default_network_services",
        "deep_app_inspection",
        "default_network_services",
        "enforce_default_app_port",
        "entries",
        "extended_log",
        "force_inclusion_ssl_di_sigs",
        "name",
        "options",
        "other_application_action",
        "other_application_log",
        "p2p_black_list",
        "p2p_block_list",
        "replacemsg_group",
        "unknown_application_action",
        "unknown_application_log",
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
        ["p2p_block_list"],
        ["options"],
        ["entries", "protocols"],
        ["entries", "vendor"],
        ["entries", "technology"],
        ["entries", "behavior"],
        ["entries", "popularity"],
        ["default_network_services", "services"],
        ["p2p_black_list"],
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


def application_list(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    application_list_data = data["application_list"]
    application_list_data = flatten_multilists_attributes(application_list_data)
    filtered_data = underscore_to_hyphen(
        filter_application_list_data(application_list_data)
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("application", "list", filtered_data, vdom=vdom)
        current_data = fos.get("application", "list", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]), serialize(filtered_data)
                )
                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_data["results"][0], "after": filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    if state == "present" or state is True:
        return fos.set("application", "list", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete("application", "list", mkey=filtered_data["name"], vdom=vdom)
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


def fortios_application(data, fos, check_mode):

    fos.do_member_operation("application", "list")
    if data["application_list"]:
        resp = application_list(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("application_list"))
    if check_mode:
        return resp
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
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "required": True,
        },
        "comment": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "replacemsg_group": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "extended_log": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "other_application_action": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "pass",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "block",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "app_replacemsg": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "other_application_log": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "enforce_default_app_port": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
            ],
        },
        "force_inclusion_ssl_di_sigs": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": False,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.0": True,
                    },
                },
            ],
        },
        "unknown_application_action": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "pass",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "block",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "unknown_application_log": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "p2p_block_list": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "list",
            "options": [
                {
                    "value": "skype",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                    },
                },
                {
                    "value": "edonkey",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                    },
                },
                {
                    "value": "bittorrent",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                    },
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "deep_app_inspection": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "options": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "list",
            "options": [
                {
                    "value": "allow-dns",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "allow-icmp",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "allow-http",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "allow-ssl",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "allow-quic",
                    "revisions": {
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
        "entries": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "integer",
                    "required": True,
                },
                "risk": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "level": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                "category": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                "application": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                "protocols": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "vendor": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "technology": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "behavior": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "list",
                    "multiple_values": True,
                    "elements": "str",
                },
                "popularity": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "list",
                    "options": [
                        {
                            "value": "1",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "2",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "3",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "4",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "5",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "exclusion": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.2.7": True,
                            },
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": False,
                        "v6.4.0": False,
                        "v6.2.7": True,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                "parameters": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "integer",
                            "required": True,
                        },
                        "members": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "id": {
                                    "revisions": {
                                        "v7.4.0": True,
                                        "v7.2.4": True,
                                        "v7.2.2": True,
                                        "v7.2.1": True,
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v6.4.4": True,
                                        "v6.4.1": True,
                                        "v6.4.0": True,
                                    },
                                    "type": "integer",
                                    "required": True,
                                },
                                "name": {
                                    "revisions": {
                                        "v7.4.0": True,
                                        "v7.2.4": True,
                                        "v7.2.2": True,
                                        "v7.2.1": True,
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v6.4.4": True,
                                        "v6.4.1": True,
                                        "v6.4.0": True,
                                    },
                                    "type": "string",
                                },
                                "value": {
                                    "revisions": {
                                        "v7.4.0": True,
                                        "v7.2.4": True,
                                        "v7.2.2": True,
                                        "v7.2.1": True,
                                        "v7.2.0": True,
                                        "v7.0.8": True,
                                        "v7.0.7": True,
                                        "v7.0.6": True,
                                        "v7.0.5": True,
                                        "v7.0.4": True,
                                        "v7.0.3": True,
                                        "v7.0.2": True,
                                        "v7.0.1": True,
                                        "v7.0.0": True,
                                        "v6.4.4": True,
                                        "v6.4.1": True,
                                        "v6.4.0": True,
                                    },
                                    "type": "string",
                                },
                            },
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": False,
                                "v6.2.5": False,
                                "v6.2.3": False,
                                "v6.2.0": False,
                                "v6.0.5": False,
                                "v6.0.11": False,
                                "v6.0.0": False,
                            },
                        },
                        "value": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "string",
                        },
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                "action": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "pass",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "reset",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "log": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "log_packet": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "rate_count": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "integer",
                },
                "rate_duration": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "integer",
                },
                "rate_mode": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "periodical",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "continuous",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "rate_track": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "src-ip",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "dest-ip",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "dhcp-client-mac",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "dns-domain",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "session_ttl": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "integer",
                },
                "shaper": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                },
                "shaper_reverse": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                },
                "per_ip_shaper": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                },
                "quarantine": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "none",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "attacker",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "quarantine_expiry": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                },
                "quarantine_log": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "disable",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                        {
                            "value": "enable",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                        },
                    ],
                },
                "sub_category": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "id": {
                            "revisions": {
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "integer",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
        },
        "control_default_network_services": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
            ],
        },
        "default_network_services": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "integer",
                    "required": True,
                },
                "port": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "integer",
                },
                "services": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "list",
                    "options": [
                        {
                            "value": "http",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "ssh",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "telnet",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "ftp",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "dns",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "smtp",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "pop3",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "imap",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "snmp",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "nntp",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "https",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                    "multiple_values": True,
                    "elements": "str",
                },
                "violation_action": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                    "type": "string",
                    "options": [
                        {
                            "value": "pass",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "monitor",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                        {
                            "value": "block",
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                            },
                        },
                    ],
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "p2p_black_list": {
            "revisions": {
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "list",
            "options": [
                {
                    "value": "skype",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "edonkey",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "bittorrent",
                    "revisions": {
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
            "multiple_values": True,
            "elements": "str",
        },
    },
    "revisions": {
        "v7.4.0": True,
        "v7.2.4": True,
        "v7.2.2": True,
        "v7.2.1": True,
        "v7.2.0": True,
        "v7.0.8": True,
        "v7.0.7": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v6.4.4": True,
        "v6.4.1": True,
        "v6.4.0": True,
        "v6.2.7": True,
        "v6.2.5": True,
        "v6.2.3": True,
        "v6.2.0": True,
        "v6.0.5": True,
        "v6.0.11": True,
        "v6.0.0": True,
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
        "application_list": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["application_list"]["options"][attribute_name] = module_spec["options"][
            attribute_name
        ]
        if mkeyname and mkeyname == attribute_name:
            fields["application_list"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
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
            fos, versioned_schema, "application_list"
        )

        is_error, has_changed, result, diff = fortios_application(
            module.params, fos, module.check_mode
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
