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
module: fortios_wireless_controller_hotspot20_anqp_nai_realm
short_description: Configure network access identifier (NAI) realm in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify wireless_controller_hotspot20 feature and anqp_nai_realm category.
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
    wireless_controller_hotspot20_anqp_nai_realm:
        description:
            - Configure network access identifier (NAI) realm.
        default: null
        type: dict
        suboptions:
            nai_list:
                description:
                    - NAI list.
                type: list
                elements: dict
                suboptions:
                    eap_method:
                        description:
                            - EAP Methods.
                        type: list
                        elements: dict
                        suboptions:
                            auth_param:
                                description:
                                    - EAP auth param.
                                type: list
                                elements: dict
                                suboptions:
                                    id:
                                        description:
                                            - ID of authentication parameter.
                                        type: str
                                        choices:
                                            - 'non-eap-inner-auth'
                                            - 'inner-auth-eap'
                                            - 'credential'
                                            - 'tunneled-credential'
                                    index:
                                        description:
                                            - Param index.
                                        required: true
                                        type: int
                                    val:
                                        description:
                                            - Value of authentication parameter.
                                        type: str
                                        choices:
                                            - 'eap-identity'
                                            - 'eap-md5'
                                            - 'eap-tls'
                                            - 'eap-ttls'
                                            - 'eap-peap'
                                            - 'eap-sim'
                                            - 'eap-aka'
                                            - 'eap-aka-prime'
                                            - 'non-eap-pap'
                                            - 'non-eap-chap'
                                            - 'non-eap-mschap'
                                            - 'non-eap-mschapv2'
                                            - 'cred-sim'
                                            - 'cred-usim'
                                            - 'cred-nfc'
                                            - 'cred-hardware-token'
                                            - 'cred-softoken'
                                            - 'cred-certificate'
                                            - 'cred-user-pwd'
                                            - 'cred-none'
                                            - 'cred-vendor-specific'
                                            - 'tun-cred-sim'
                                            - 'tun-cred-usim'
                                            - 'tun-cred-nfc'
                                            - 'tun-cred-hardware-token'
                                            - 'tun-cred-softoken'
                                            - 'tun-cred-certificate'
                                            - 'tun-cred-user-pwd'
                                            - 'tun-cred-anonymous'
                                            - 'tun-cred-vendor-specific'
                            index:
                                description:
                                    - EAP method index.
                                required: true
                                type: int
                            method:
                                description:
                                    - EAP method type.
                                type: str
                                choices:
                                    - 'eap-identity'
                                    - 'eap-md5'
                                    - 'eap-tls'
                                    - 'eap-ttls'
                                    - 'eap-peap'
                                    - 'eap-sim'
                                    - 'eap-aka'
                                    - 'eap-aka-prime'
                    encoding:
                        description:
                            - Enable/disable format in accordance with IETF RFC 4282.
                        type: str
                        choices:
                            - 'disable'
                            - 'enable'
                    nai_realm:
                        description:
                            - Configure NAI realms (delimited by a semi-colon character).
                        type: str
                    name:
                        description:
                            - NAI realm name.
                        required: true
                        type: str
            name:
                description:
                    - NAI realm list name.
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
  - name: Configure network access identifier (NAI) realm.
    fortios_wireless_controller_hotspot20_anqp_nai_realm:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      wireless_controller_hotspot20_anqp_nai_realm:
        nai_list:
         -
            eap_method:
             -
                auth_param:
                 -
                    id:  "6"
                    index: "0"
                    val: "eap-identity"
                index: "0"
                method: "eap-identity"
            encoding: "disable"
            nai_realm: "<your_own_value>"
            name: "default_name_13"
        name: "default_name_14"

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


def filter_wireless_controller_hotspot20_anqp_nai_realm_data(json):
    option_list = ["nai_list", "name"]

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


def wireless_controller_hotspot20_anqp_nai_realm(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    wireless_controller_hotspot20_anqp_nai_realm_data = data[
        "wireless_controller_hotspot20_anqp_nai_realm"
    ]
    filtered_data = underscore_to_hyphen(
        filter_wireless_controller_hotspot20_anqp_nai_realm_data(
            wireless_controller_hotspot20_anqp_nai_realm_data
        )
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey(
            "wireless-controller.hotspot20", "anqp-nai-realm", filtered_data, vdom=vdom
        )
        current_data = fos.get(
            "wireless-controller.hotspot20", "anqp-nai-realm", vdom=vdom, mkey=mkey
        )
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
        return fos.set(
            "wireless-controller.hotspot20",
            "anqp-nai-realm",
            data=filtered_data,
            vdom=vdom,
        )

    elif state == "absent":
        return fos.delete(
            "wireless-controller.hotspot20",
            "anqp-nai-realm",
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


def fortios_wireless_controller_hotspot20(data, fos, check_mode):

    fos.do_member_operation("wireless-controller.hotspot20", "anqp-nai-realm")
    if data["wireless_controller_hotspot20_anqp_nai_realm"]:
        resp = wireless_controller_hotspot20_anqp_nai_realm(data, fos, check_mode)
    else:
        fos._module.fail_json(
            msg="missing task body: %s"
            % ("wireless_controller_hotspot20_anqp_nai_realm")
        )
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
        "nai_list": {
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
                "encoding": {
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
                "nai_realm": {
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
                "eap_method": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "index": {
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
                        "method": {
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
                                    "value": "eap-identity",
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
                                    "value": "eap-md5",
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
                                    "value": "eap-tls",
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
                                    "value": "eap-ttls",
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
                                    "value": "eap-peap",
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
                                    "value": "eap-sim",
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
                                    "value": "eap-aka",
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
                                    "value": "eap-aka-prime",
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
                        "auth_param": {
                            "type": "list",
                            "elements": "dict",
                            "children": {
                                "index": {
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
                                    "type": "string",
                                    "options": [
                                        {
                                            "value": "non-eap-inner-auth",
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
                                            "value": "inner-auth-eap",
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
                                            "value": "credential",
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
                                            "value": "tunneled-credential",
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
                                "val": {
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
                                            "value": "eap-identity",
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
                                            "value": "eap-md5",
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
                                            "value": "eap-tls",
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
                                            "value": "eap-ttls",
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
                                            "value": "eap-peap",
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
                                            "value": "eap-sim",
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
                                            "value": "eap-aka",
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
                                            "value": "eap-aka-prime",
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
                                            "value": "non-eap-pap",
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
                                            "value": "non-eap-chap",
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
                                            "value": "non-eap-mschap",
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
                                            "value": "non-eap-mschapv2",
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
                                            "value": "cred-sim",
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
                                            "value": "cred-usim",
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
                                            "value": "cred-nfc",
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
                                            "value": "cred-hardware-token",
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
                                            "value": "cred-softoken",
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
                                            "value": "cred-certificate",
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
                                            "value": "cred-user-pwd",
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
                                            "value": "cred-none",
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
                                            "value": "cred-vendor-specific",
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
                                            "value": "tun-cred-sim",
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
                                            "value": "tun-cred-usim",
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
                                            "value": "tun-cred-nfc",
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
                                            "value": "tun-cred-hardware-token",
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
                                            "value": "tun-cred-softoken",
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
                                            "value": "tun-cred-certificate",
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
                                            "value": "tun-cred-user-pwd",
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
                                            "value": "tun-cred-anonymous",
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
                                            "value": "tun-cred-vendor-specific",
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
        "wireless_controller_hotspot20_anqp_nai_realm": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["wireless_controller_hotspot20_anqp_nai_realm"]["options"][
            attribute_name
        ] = module_spec["options"][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["wireless_controller_hotspot20_anqp_nai_realm"]["options"][
                attribute_name
            ]["required"] = True

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
            fos, versioned_schema, "wireless_controller_hotspot20_anqp_nai_realm"
        )

        is_error, has_changed, result, diff = fortios_wireless_controller_hotspot20(
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
