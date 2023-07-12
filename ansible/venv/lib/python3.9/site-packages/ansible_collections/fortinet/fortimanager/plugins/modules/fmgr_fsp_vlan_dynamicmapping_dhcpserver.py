#!/usr/bin/python
from __future__ import absolute_import, division, print_function
# Copyright 2019-2023 Fortinet, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

__metaclass__ = type

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'metadata_version': '1.1'}

DOCUMENTATION = '''
---
module: fmgr_fsp_vlan_dynamicmapping_dhcpserver
short_description: Configure DHCP servers.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.0.0"
author:
    - Xinwei Du (@dux-fortinet)
    - Xing Li (@lix-fortinet)
    - Jie Xue (@JieX19)
    - Link Zheng (@chillancezen)
    - Frank Shen (@fshen01)
    - Hongbin Lu (@fgtdev-hblu)
notes:
    - Running in workspace locking mode is supported in this FortiManager module, the top
      level parameters workspace_locking_adom and workspace_locking_timeout help do the work.
    - To create or update an object, use state present directive.
    - To delete an object, use state absent directive.
    - Normally, running one module can fail when a non-zero rc is returned. you can also override
      the conditions to fail or succeed with parameters rc_failed and rc_succeeded

options:
    access_token:
        description: The token to access FortiManager without using username and password.
        required: false
        type: str
    bypass_validation:
        description: Only set to True when module schema diffs with FortiManager API structure, module continues to execute without validating parameters.
        required: false
        type: bool
        default: false
    enable_log:
        description: Enable/Disable logging for task.
        required: false
        type: bool
        default: false
    forticloud_access_token:
        description: Authenticate Ansible client with forticloud API access token.
        required: false
        type: str
    proposed_method:
        description: The overridden method for the underlying Json RPC request.
        required: false
        type: str
        choices:
          - update
          - set
          - add
    rc_succeeded:
        description: The rc codes list with which the conditions to succeed will be overriden.
        type: list
        required: false
        elements: int
    rc_failed:
        description: The rc codes list with which the conditions to fail will be overriden.
        type: list
        required: false
        elements: int
    workspace_locking_adom:
        description: The adom to lock for FortiManager running in workspace mode, the value can be global and others including root.
        required: false
        type: str
    workspace_locking_timeout:
        description: The maximum time in seconds to wait for other user to release the workspace lock.
        required: false
        type: int
        default: 300
    adom:
        description: the parameter (adom) in requested url
        type: str
        required: true
    vlan:
        description: the parameter (vlan) in requested url
        type: str
        required: true
    dynamic_mapping:
        description: the parameter (dynamic_mapping) in requested url
        type: str
        required: true
    fsp_vlan_dynamicmapping_dhcpserver:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            auto-configuration:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            conflicted-ip-timeout:
                type: int
                description: no description
            ddns-auth:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'tsig'
            ddns-key:
                type: str
                description: no description
            ddns-keyname:
                type: str
                description: no description
            ddns-server-ip:
                type: str
                description: no description
            ddns-ttl:
                type: int
                description: no description
            ddns-update:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ddns-update-override:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            ddns-zone:
                type: str
                description: no description
            default-gateway:
                type: str
                description: no description
            dns-server1:
                type: str
                description: no description
            dns-server2:
                type: str
                description: no description
            dns-server3:
                type: str
                description: no description
            dns-service:
                type: str
                description: no description
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            domain:
                type: str
                description: no description
            enable:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            exclude-range:
                description: description
                type: list
                elements: dict
                suboptions:
                    end-ip:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    start-ip:
                        type: str
                        description: no description
                    vci-match:
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci-string:
                        description: description
                        type: str
                    lease-time:
                        type: int
                        description: Lease time in seconds, 0 means default lease time.
                    uci-match:
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci-string:
                        description: description
                        type: str
            filename:
                type: str
                description: no description
            forticlient-on-net-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: no description
            interface:
                type: str
                description: no description
            ip-mode:
                type: str
                description: no description
                choices:
                    - 'range'
                    - 'usrgrp'
            ip-range:
                description: description
                type: list
                elements: dict
                suboptions:
                    end-ip:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    start-ip:
                        type: str
                        description: no description
                    vci-match:
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci-string:
                        description: description
                        type: str
                    lease-time:
                        type: int
                        description: Lease time in seconds, 0 means default lease time.
                    uci-match:
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci-string:
                        description: description
                        type: str
            ipsec-lease-hold:
                type: int
                description: no description
            lease-time:
                type: int
                description: no description
            mac-acl-default-action:
                type: str
                description: no description
                choices:
                    - 'assign'
                    - 'block'
            netmask:
                type: str
                description: no description
            next-server:
                type: str
                description: no description
            ntp-server1:
                type: str
                description: no description
            ntp-server2:
                type: str
                description: no description
            ntp-server3:
                type: str
                description: no description
            ntp-service:
                type: str
                description: no description
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            option1:
                description: description
                type: str
            option2:
                description: description
                type: str
            option3:
                description: description
                type: str
            option4:
                type: str
                description: no description
            option5:
                type: str
                description: no description
            option6:
                type: str
                description: no description
            options:
                description: description
                type: list
                elements: dict
                suboptions:
                    code:
                        type: int
                        description: no description
                    id:
                        type: int
                        description: no description
                    ip:
                        description: description
                        type: str
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'hex'
                            - 'string'
                            - 'ip'
                            - 'fqdn'
                    value:
                        type: str
                        description: no description
                    vci-match:
                        type: str
                        description: Enable/disable vendor class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    vci-string:
                        description: description
                        type: str
                    uci-match:
                        type: str
                        description: Enable/disable user class identifier
                        choices:
                            - 'disable'
                            - 'enable'
                    uci-string:
                        description: description
                        type: str
            reserved-address:
                description: description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description: no description
                        choices:
                            - 'assign'
                            - 'block'
                            - 'reserved'
                    circuit-id:
                        type: str
                        description: no description
                    circuit-id-type:
                        type: str
                        description: no description
                        choices:
                            - 'hex'
                            - 'string'
                    description:
                        type: str
                        description: no description
                    id:
                        type: int
                        description: no description
                    ip:
                        type: str
                        description: no description
                    mac:
                        type: str
                        description: no description
                    remote-id:
                        type: str
                        description: no description
                    remote-id-type:
                        type: str
                        description: no description
                        choices:
                            - 'hex'
                            - 'string'
                    type:
                        type: str
                        description: no description
                        choices:
                            - 'mac'
                            - 'option82'
            server-type:
                type: str
                description: no description
                choices:
                    - 'regular'
                    - 'ipsec'
            status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            tftp-server:
                description: description
                type: str
            timezone:
                type: str
                description: no description
                choices:
                    - '00'
                    - '01'
                    - '02'
                    - '03'
                    - '04'
                    - '05'
                    - '06'
                    - '07'
                    - '08'
                    - '09'
                    - '10'
                    - '11'
                    - '12'
                    - '13'
                    - '14'
                    - '15'
                    - '16'
                    - '17'
                    - '18'
                    - '19'
                    - '20'
                    - '21'
                    - '22'
                    - '23'
                    - '24'
                    - '25'
                    - '26'
                    - '27'
                    - '28'
                    - '29'
                    - '30'
                    - '31'
                    - '32'
                    - '33'
                    - '34'
                    - '35'
                    - '36'
                    - '37'
                    - '38'
                    - '39'
                    - '40'
                    - '41'
                    - '42'
                    - '43'
                    - '44'
                    - '45'
                    - '46'
                    - '47'
                    - '48'
                    - '49'
                    - '50'
                    - '51'
                    - '52'
                    - '53'
                    - '54'
                    - '55'
                    - '56'
                    - '57'
                    - '58'
                    - '59'
                    - '60'
                    - '61'
                    - '62'
                    - '63'
                    - '64'
                    - '65'
                    - '66'
                    - '67'
                    - '68'
                    - '69'
                    - '70'
                    - '71'
                    - '72'
                    - '73'
                    - '74'
                    - '75'
                    - '76'
                    - '77'
                    - '78'
                    - '79'
                    - '80'
                    - '81'
                    - '82'
                    - '83'
                    - '84'
                    - '85'
                    - '86'
                    - '87'
            timezone-option:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'default'
                    - 'specify'
            vci-match:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            vci-string:
                description: description
                type: str
            wifi-ac1:
                type: str
                description: no description
            wifi-ac2:
                type: str
                description: no description
            wifi-ac3:
                type: str
                description: no description
            wins-server1:
                type: str
                description: no description
            wins-server2:
                type: str
                description: no description
            dns-server4:
                type: str
                description: no description
            wifi-ac-service:
                type: str
                description: no description
                choices:
                    - 'specify'
                    - 'local'
            auto-managed-status:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            dhcp-settings-from-fortiipam:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            relay-agent:
                type: str
                description: Relay agent IP.
            shared-subnet:
                type: str
                description: Enable/disable shared subnet.
                choices:
                    - 'disable'
                    - 'enable'

'''

EXAMPLES = '''
 - hosts: fortimanager-inventory
   collections:
     - fortinet.fortimanager
   connection: httpapi
   vars:
      ansible_httpapi_use_ssl: True
      ansible_httpapi_validate_certs: False
      ansible_httpapi_port: 443
   tasks:
    - name: Configure DHCP servers.
      fmgr_fsp_vlan_dynamicmapping_dhcpserver:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         vlan: <your own value>
         dynamic_mapping: <your own value>
         fsp_vlan_dynamicmapping_dhcpserver:
            auto-configuration: <value in [disable, enable]>
            conflicted-ip-timeout: <value of integer>
            ddns-auth: <value in [disable, tsig]>
            ddns-key: <value of string>
            ddns-keyname: <value of string>
            ddns-server-ip: <value of string>
            ddns-ttl: <value of integer>
            ddns-update: <value in [disable, enable]>
            ddns-update-override: <value in [disable, enable]>
            ddns-zone: <value of string>
            default-gateway: <value of string>
            dns-server1: <value of string>
            dns-server2: <value of string>
            dns-server3: <value of string>
            dns-service: <value in [default, specify, local]>
            domain: <value of string>
            enable: <value in [disable, enable]>
            exclude-range:
              -
                  end-ip: <value of string>
                  id: <value of integer>
                  start-ip: <value of string>
                  vci-match: <value in [disable, enable]>
                  vci-string: <value of string>
                  lease-time: <value of integer>
                  uci-match: <value in [disable, enable]>
                  uci-string: <value of string>
            filename: <value of string>
            forticlient-on-net-status: <value in [disable, enable]>
            id: <value of integer>
            interface: <value of string>
            ip-mode: <value in [range, usrgrp]>
            ip-range:
              -
                  end-ip: <value of string>
                  id: <value of integer>
                  start-ip: <value of string>
                  vci-match: <value in [disable, enable]>
                  vci-string: <value of string>
                  lease-time: <value of integer>
                  uci-match: <value in [disable, enable]>
                  uci-string: <value of string>
            ipsec-lease-hold: <value of integer>
            lease-time: <value of integer>
            mac-acl-default-action: <value in [assign, block]>
            netmask: <value of string>
            next-server: <value of string>
            ntp-server1: <value of string>
            ntp-server2: <value of string>
            ntp-server3: <value of string>
            ntp-service: <value in [default, specify, local]>
            option1: <value of string>
            option2: <value of string>
            option3: <value of string>
            option4: <value of string>
            option5: <value of string>
            option6: <value of string>
            options:
              -
                  code: <value of integer>
                  id: <value of integer>
                  ip: <value of string>
                  type: <value in [hex, string, ip, ...]>
                  value: <value of string>
                  vci-match: <value in [disable, enable]>
                  vci-string: <value of string>
                  uci-match: <value in [disable, enable]>
                  uci-string: <value of string>
            reserved-address:
              -
                  action: <value in [assign, block, reserved]>
                  circuit-id: <value of string>
                  circuit-id-type: <value in [hex, string]>
                  description: <value of string>
                  id: <value of integer>
                  ip: <value of string>
                  mac: <value of string>
                  remote-id: <value of string>
                  remote-id-type: <value in [hex, string]>
                  type: <value in [mac, option82]>
            server-type: <value in [regular, ipsec]>
            status: <value in [disable, enable]>
            tftp-server: <value of string>
            timezone: <value in [00, 01, 02, ...]>
            timezone-option: <value in [disable, default, specify]>
            vci-match: <value in [disable, enable]>
            vci-string: <value of string>
            wifi-ac1: <value of string>
            wifi-ac2: <value of string>
            wifi-ac3: <value of string>
            wins-server1: <value of string>
            wins-server2: <value of string>
            dns-server4: <value of string>
            wifi-ac-service: <value in [specify, local]>
            auto-managed-status: <value in [disable, enable]>
            dhcp-settings-from-fortiipam: <value in [disable, enable]>
            relay-agent: <value of string>
            shared-subnet: <value in [disable, enable]>

'''

RETURN = '''
meta:
    description: The result of the request.
    type: dict
    returned: always
    contains:
        request_url:
            description: The full url requested.
            returned: always
            type: str
            sample: /sys/login/user
        response_code:
            description: The status of api request.
            returned: always
            type: int
            sample: 0
        response_data:
            description: The api response.
            type: list
            returned: always
        response_message:
            description: The descriptive message of the api response.
            type: str
            returned: always
            sample: OK.
        system_information:
            description: The information of the target system.
            type: dict
            returned: always
rc:
    description: The status the request.
    type: int
    returned: always
    sample: 0
version_check_warning:
    description: Warning if the parameters used in the playbook are not supported by the current FortiManager version.
    type: list
    returned: complex
'''
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import NAPIManager
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_galaxy_version
from ansible_collections.fortinet.fortimanager.plugins.module_utils.napi import check_parameter_bypass


def main():
    jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/{dhcp-server}',
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/dhcp-server/{dhcp-server}'
    ]

    url_params = ['adom', 'vlan', 'dynamic_mapping']
    module_primary_key = None
    module_arg_spec = {
        'access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'bypass_validation': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'enable_log': {
            'type': 'bool',
            'required': False,
            'default': False
        },
        'forticloud_access_token': {
            'type': 'str',
            'required': False,
            'no_log': True
        },
        'proposed_method': {
            'type': 'str',
            'required': False,
            'choices': [
                'set',
                'update',
                'add'
            ]
        },
        'rc_succeeded': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'rc_failed': {
            'required': False,
            'type': 'list',
            'elements': 'int'
        },
        'workspace_locking_adom': {
            'type': 'str',
            'required': False
        },
        'workspace_locking_timeout': {
            'type': 'int',
            'required': False,
            'default': 300
        },
        'adom': {
            'required': True,
            'type': 'str'
        },
        'vlan': {
            'required': True,
            'type': 'str'
        },
        'dynamic_mapping': {
            'required': True,
            'type': 'str'
        },
        'fsp_vlan_dynamicmapping_dhcpserver': {
            'required': False,
            'type': 'dict',
            'revision': {
                '6.0.0': True,
                '6.2.0': True,
                '6.2.1': True,
                '6.2.2': True,
                '6.2.3': True,
                '6.2.5': True,
                '6.2.6': True,
                '6.2.7': True,
                '6.2.8': True,
                '6.2.9': True,
                '6.2.10': True,
                '6.4.0': True,
                '6.4.1': True,
                '6.4.2': True,
                '6.4.3': True,
                '6.4.4': True,
                '6.4.5': True,
                '6.4.6': True,
                '6.4.7': True,
                '6.4.8': True,
                '6.4.9': True,
                '6.4.10': True,
                '6.4.11': True,
                '7.0.0': True,
                '7.0.1': True,
                '7.0.2': True,
                '7.0.3': True,
                '7.0.4': True,
                '7.0.5': True,
                '7.0.6': True,
                '7.0.7': True,
                '7.2.0': True,
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'options': {
                'auto-configuration': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'conflicted-ip-timeout': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'ddns-auth': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'tsig'
                    ],
                    'type': 'str'
                },
                'ddns-key': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ddns-keyname': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ddns-server-ip': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ddns-ttl': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'ddns-update': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ddns-update-override': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'ddns-zone': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'default-gateway': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'dns-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'dns-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'dns-server3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'dns-service': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'default',
                        'specify',
                        'local'
                    ],
                    'type': 'str'
                },
                'domain': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'enable': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'exclude-range': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'end-ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'start-ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'vci-match': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'vci-string': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'lease-time': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'uci-match': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uci-string': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'filename': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'forticlient-on-net-status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'id': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'interface': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': False,
                        '6.2.5': False,
                        '6.4.0': False,
                        '6.4.2': False,
                        '6.4.5': False,
                        '7.0.0': False,
                        '7.2.0': False,
                        '6.2.0': True,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
                        '6.4.6': False,
                        '6.4.7': False,
                        '6.4.8': False,
                        '6.4.9': False,
                        '6.4.10': False,
                        '6.4.11': False,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'str'
                },
                'ip-mode': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'range',
                        'usrgrp'
                    ],
                    'type': 'str'
                },
                'ip-range': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'end-ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'start-ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'vci-match': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'vci-string': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'lease-time': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'uci-match': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uci-string': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ipsec-lease-hold': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'lease-time': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'mac-acl-default-action': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'assign',
                        'block'
                    ],
                    'type': 'str'
                },
                'netmask': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'next-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ntp-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ntp-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ntp-server3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ntp-service': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'default',
                        'specify',
                        'local'
                    ],
                    'type': 'str'
                },
                'option1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'option2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'option3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'option4': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'option5': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'option6': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'options': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'code': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'hex',
                                'string',
                                'ip',
                                'fqdn'
                            ],
                            'type': 'str'
                        },
                        'value': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'vci-match': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'vci-string': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'uci-match': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'uci-string': {
                            'required': False,
                            'revision': {
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'reserved-address': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'assign',
                                'block',
                                'reserved'
                            ],
                            'type': 'str'
                        },
                        'circuit-id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'circuit-id-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'hex',
                                'string'
                            ],
                            'type': 'str'
                        },
                        'description': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'mac': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'remote-id': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'remote-id-type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'hex',
                                'string'
                            ],
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '6.0.0': True,
                                '6.2.1': True,
                                '6.2.3': True,
                                '6.2.5': True,
                                '6.4.0': True,
                                '6.4.2': True,
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': True,
                                '6.2.2': True,
                                '6.2.6': True,
                                '6.2.7': True,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
                                '6.4.1': True,
                                '6.4.3': True,
                                '6.4.4': True,
                                '6.4.6': True,
                                '6.4.7': True,
                                '6.4.8': True,
                                '6.4.9': True,
                                '6.4.10': True,
                                '6.4.11': True,
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': True,
                                '7.0.4': True,
                                '7.0.5': True,
                                '7.0.6': True,
                                '7.0.7': True,
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'mac',
                                'option82'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'server-type': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'regular',
                        'ipsec'
                    ],
                    'type': 'str'
                },
                'status': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'tftp-server': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'timezone': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        '00',
                        '01',
                        '02',
                        '03',
                        '04',
                        '05',
                        '06',
                        '07',
                        '08',
                        '09',
                        '10',
                        '11',
                        '12',
                        '13',
                        '14',
                        '15',
                        '16',
                        '17',
                        '18',
                        '19',
                        '20',
                        '21',
                        '22',
                        '23',
                        '24',
                        '25',
                        '26',
                        '27',
                        '28',
                        '29',
                        '30',
                        '31',
                        '32',
                        '33',
                        '34',
                        '35',
                        '36',
                        '37',
                        '38',
                        '39',
                        '40',
                        '41',
                        '42',
                        '43',
                        '44',
                        '45',
                        '46',
                        '47',
                        '48',
                        '49',
                        '50',
                        '51',
                        '52',
                        '53',
                        '54',
                        '55',
                        '56',
                        '57',
                        '58',
                        '59',
                        '60',
                        '61',
                        '62',
                        '63',
                        '64',
                        '65',
                        '66',
                        '67',
                        '68',
                        '69',
                        '70',
                        '71',
                        '72',
                        '73',
                        '74',
                        '75',
                        '76',
                        '77',
                        '78',
                        '79',
                        '80',
                        '81',
                        '82',
                        '83',
                        '84',
                        '85',
                        '86',
                        '87'
                    ],
                    'type': 'str'
                },
                'timezone-option': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'default',
                        'specify'
                    ],
                    'type': 'str'
                },
                'vci-match': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'vci-string': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'wifi-ac1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'wifi-ac2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'wifi-ac3': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'wins-server1': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'wins-server2': {
                    'required': False,
                    'revision': {
                        '6.0.0': True,
                        '6.2.1': True,
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': True,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'dns-server4': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'wifi-ac-service': {
                    'required': False,
                    'revision': {
                        '6.2.3': True,
                        '6.2.5': True,
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': True,
                        '6.2.6': True,
                        '6.2.7': True,
                        '6.2.8': True,
                        '6.2.9': True,
                        '6.2.10': True,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'specify',
                        'local'
                    ],
                    'type': 'str'
                },
                'auto-managed-status': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'dhcp-settings-from-fortiipam': {
                    'required': False,
                    'revision': {
                        '6.4.0': True,
                        '6.4.2': True,
                        '6.4.5': True,
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': True,
                        '6.4.3': True,
                        '6.4.4': True,
                        '6.4.6': True,
                        '6.4.7': True,
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': True,
                        '7.0.4': True,
                        '7.0.5': True,
                        '7.0.6': True,
                        '7.0.7': True,
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'relay-agent': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'shared-subnet': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_dhcpserver'),
                           supports_check_mode=False)

    fmgr = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        connection.set_option('access_token', module.params['access_token'] if 'access_token' in module.params else None)
        connection.set_option('enable_log', module.params['enable_log'] if 'enable_log' in module.params else False)
        connection.set_option('forticloud_access_token',
                              module.params['forticloud_access_token'] if 'forticloud_access_token' in module.params else None)
        fmgr = NAPIManager(jrpc_urls, perobject_jrpc_urls, module_primary_key, url_params, module, connection, top_level_schema_name='data')
        fmgr.validate_parameters(params_validation_blob)
        fmgr.process_partial_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
