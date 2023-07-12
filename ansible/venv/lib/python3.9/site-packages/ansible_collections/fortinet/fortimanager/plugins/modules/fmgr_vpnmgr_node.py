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
module: fmgr_vpnmgr_node
short_description: VPN node for VPN Manager.
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
    state:
        description: The directive to create, update or delete an object.
        type: str
        required: true
        choices:
          - present
          - absent
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
    vpnmgr_node:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            add-route:
                type: str
                description: Add-Route.
                choices:
                    - 'disable'
                    - 'enable'
            assign-ip:
                type: str
                description: Assign-Ip.
                choices:
                    - 'disable'
                    - 'enable'
            assign-ip-from:
                type: str
                description: Assign-Ip-From.
                choices:
                    - 'range'
                    - 'usrgrp'
                    - 'dhcp'
                    - 'name'
            authpasswd:
                description: Authpasswd.
                type: str
            authusr:
                type: str
                description: Authusr.
            authusrgrp:
                type: str
                description: Authusrgrp.
            auto-configuration:
                type: str
                description: Auto-Configuration.
                choices:
                    - 'disable'
                    - 'enable'
            automatic_routing:
                type: str
                description: Automatic_Routing.
                choices:
                    - 'disable'
                    - 'enable'
            banner:
                type: str
                description: Banner.
            default-gateway:
                type: str
                description: Default-Gateway.
            dhcp-server:
                type: str
                description: Dhcp-Server.
                choices:
                    - 'disable'
                    - 'enable'
            dns-mode:
                type: str
                description: Dns-Mode.
                choices:
                    - 'auto'
                    - 'manual'
            dns-service:
                type: str
                description: Dns-Service.
                choices:
                    - 'default'
                    - 'specify'
                    - 'local'
            domain:
                type: str
                description: Domain.
            extgw:
                type: str
                description: Extgw.
            extgw_hubip:
                type: str
                description: Extgw_Hubip.
            extgw_p2_per_net:
                type: str
                description: Extgw_P2_Per_Net.
                choices:
                    - 'disable'
                    - 'enable'
            extgwip:
                type: str
                description: Extgwip.
            hub_iface:
                type: str
                description: Hub_Iface.
            id:
                type: int
                description: Id.
            iface:
                type: str
                description: Iface.
            ip-range:
                description: Ip-Range.
                type: list
                elements: dict
                suboptions:
                    end-ip:
                        type: str
                        description: End-Ip.
                    id:
                        type: int
                        description: Id.
                    start-ip:
                        type: str
                        description: Start-Ip.
            ipsec-lease-hold:
                type: int
                description: Ipsec-Lease-Hold.
            ipv4-dns-server1:
                type: str
                description: Ipv4-Dns-Server1.
            ipv4-dns-server2:
                type: str
                description: Ipv4-Dns-Server2.
            ipv4-dns-server3:
                type: str
                description: Ipv4-Dns-Server3.
            ipv4-end-ip:
                type: str
                description: Ipv4-End-Ip.
            ipv4-exclude-range:
                description: Ipv4-Exclude-Range.
                type: list
                elements: dict
                suboptions:
                    end-ip:
                        type: str
                        description: End-Ip.
                    id:
                        type: int
                        description: Id.
                    start-ip:
                        type: str
                        description: Start-Ip.
            ipv4-netmask:
                type: str
                description: Ipv4-Netmask.
            ipv4-split-include:
                type: str
                description: Ipv4-Split-Include.
            ipv4-start-ip:
                type: str
                description: Ipv4-Start-Ip.
            ipv4-wins-server1:
                type: str
                description: Ipv4-Wins-Server1.
            ipv4-wins-server2:
                type: str
                description: Ipv4-Wins-Server2.
            local-gw:
                type: str
                description: Local-Gw.
            localid:
                type: str
                description: Localid.
            mode-cfg:
                type: str
                description: Mode-Cfg.
                choices:
                    - 'disable'
                    - 'enable'
            mode-cfg-ip-version:
                type: str
                description: Mode-Cfg-Ip-Version.
                choices:
                    - '4'
                    - '6'
            net-device:
                type: str
                description: Net-Device.
                choices:
                    - 'disable'
                    - 'enable'
            peer:
                type: str
                description: Peer.
            peergrp:
                type: str
                description: Peergrp.
            peerid:
                type: str
                description: Peerid.
            peertype:
                type: str
                description: Peertype.
                choices:
                    - 'any'
                    - 'one'
                    - 'dialup'
                    - 'peer'
                    - 'peergrp'
            protected_subnet:
                description: Protected_Subnet.
                type: list
                elements: dict
                suboptions:
                    addr:
                        type: str
                        description: Addr.
                    seq:
                        type: int
                        description: Seq.
            public-ip:
                type: str
                description: Public-Ip.
            role:
                type: str
                description: Role.
                choices:
                    - 'hub'
                    - 'spoke'
            route-overlap:
                type: str
                description: Route-Overlap.
                choices:
                    - 'use-old'
                    - 'use-new'
                    - 'allow'
            spoke-zone:
                type: str
                description: Spoke-Zone.
            summary_addr:
                description: Summary_Addr.
                type: list
                elements: dict
                suboptions:
                    addr:
                        type: str
                        description: Addr.
                    priority:
                        type: int
                        description: Priority.
                    seq:
                        type: int
                        description: Seq.
            tunnel-search:
                type: str
                description: Tunnel-Search.
                choices:
                    - 'selectors'
                    - 'nexthop'
            unity-support:
                type: str
                description: Unity-Support.
                choices:
                    - 'disable'
                    - 'enable'
            usrgrp:
                type: str
                description: Usrgrp.
            vpn-interface-priority:
                type: int
                description: Vpn-Interface-Priority.
            vpn-zone:
                type: str
                description: Vpn-Zone.
            vpntable:
                type: str
                description: Vpntable.
            xauthtype:
                type: str
                description: Xauthtype.
                choices:
                    - 'disable'
                    - 'client'
                    - 'pap'
                    - 'chap'
                    - 'auto'
            exchange-interface-ip:
                type: str
                description: Exchange-Interface-Ip.
                choices:
                    - 'disable'
                    - 'enable'
            hub-public-ip:
                type: str
                description: Hub-Public-Ip.
            ipv4-split-exclude:
                type: str
                description: Ipv4-Split-Exclude.
            scope member:
                description: description
                type: list
                elements: dict
                suboptions:
                    name:
                        type: str
                        description: no description
                    vdom:
                        type: str
                        description: no description
            dhcp-ra-giaddr:
                type: str
                description: no description
            encapsulation:
                type: str
                description: no description
                choices:
                    - 'tunnel-mode'
                    - 'transport-mode'
            ipv4-name:
                type: str
                description: no description
            l2tp:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auto-discovery-receiver:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            auto-discovery-sender:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            network-id:
                type: int
                description: no description
            network-overlay:
                type: str
                description: no description
                choices:
                    - 'enable'
                    - 'disable'

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
    - name: VPN node for VPN Manager.
      fmgr_vpnmgr_node:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         vpnmgr_node:
            add-route: <value in [disable, enable]>
            assign-ip: <value in [disable, enable]>
            assign-ip-from: <value in [range, usrgrp, dhcp, ...]>
            authpasswd: <value of string>
            authusr: <value of string>
            authusrgrp: <value of string>
            auto-configuration: <value in [disable, enable]>
            automatic_routing: <value in [disable, enable]>
            banner: <value of string>
            default-gateway: <value of string>
            dhcp-server: <value in [disable, enable]>
            dns-mode: <value in [auto, manual]>
            dns-service: <value in [default, specify, local]>
            domain: <value of string>
            extgw: <value of string>
            extgw_hubip: <value of string>
            extgw_p2_per_net: <value in [disable, enable]>
            extgwip: <value of string>
            hub_iface: <value of string>
            id: <value of integer>
            iface: <value of string>
            ip-range:
              -
                  end-ip: <value of string>
                  id: <value of integer>
                  start-ip: <value of string>
            ipsec-lease-hold: <value of integer>
            ipv4-dns-server1: <value of string>
            ipv4-dns-server2: <value of string>
            ipv4-dns-server3: <value of string>
            ipv4-end-ip: <value of string>
            ipv4-exclude-range:
              -
                  end-ip: <value of string>
                  id: <value of integer>
                  start-ip: <value of string>
            ipv4-netmask: <value of string>
            ipv4-split-include: <value of string>
            ipv4-start-ip: <value of string>
            ipv4-wins-server1: <value of string>
            ipv4-wins-server2: <value of string>
            local-gw: <value of string>
            localid: <value of string>
            mode-cfg: <value in [disable, enable]>
            mode-cfg-ip-version: <value in [4, 6]>
            net-device: <value in [disable, enable]>
            peer: <value of string>
            peergrp: <value of string>
            peerid: <value of string>
            peertype: <value in [any, one, dialup, ...]>
            protected_subnet:
              -
                  addr: <value of string>
                  seq: <value of integer>
            public-ip: <value of string>
            role: <value in [hub, spoke]>
            route-overlap: <value in [use-old, use-new, allow]>
            spoke-zone: <value of string>
            summary_addr:
              -
                  addr: <value of string>
                  priority: <value of integer>
                  seq: <value of integer>
            tunnel-search: <value in [selectors, nexthop]>
            unity-support: <value in [disable, enable]>
            usrgrp: <value of string>
            vpn-interface-priority: <value of integer>
            vpn-zone: <value of string>
            vpntable: <value of string>
            xauthtype: <value in [disable, client, pap, ...]>
            exchange-interface-ip: <value in [disable, enable]>
            hub-public-ip: <value of string>
            ipv4-split-exclude: <value of string>
            scope member:
              -
                  name: <value of string>
                  vdom: <value of string>
            dhcp-ra-giaddr: <value of string>
            encapsulation: <value in [tunnel-mode, transport-mode]>
            ipv4-name: <value of string>
            l2tp: <value in [disable, enable]>
            auto-discovery-receiver: <value in [disable, enable]>
            auto-discovery-sender: <value in [disable, enable]>
            network-id: <value of integer>
            network-overlay: <value in [enable, disable]>

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
        '/pm/config/adom/{adom}/obj/vpnmgr/node',
        '/pm/config/global/obj/vpnmgr/node'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/vpnmgr/node/{node}',
        '/pm/config/global/obj/vpnmgr/node/{node}'
    ]

    url_params = ['adom']
    module_primary_key = 'id'
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
        'state': {
            'type': 'str',
            'required': True,
            'choices': [
                'present',
                'absent'
            ]
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
        'vpnmgr_node': {
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
                'add-route': {
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
                'assign-ip': {
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
                'assign-ip-from': {
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
                        'usrgrp',
                        'dhcp',
                        'name'
                    ],
                    'type': 'str'
                },
                'authpasswd': {
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
                    'no_log': True,
                    'type': 'str'
                },
                'authusr': {
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
                'authusrgrp': {
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
                'automatic_routing': {
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
                'banner': {
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
                'dhcp-server': {
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
                'dns-mode': {
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
                        'auto',
                        'manual'
                    ],
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
                'extgw': {
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
                'extgw_hubip': {
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
                'extgw_p2_per_net': {
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
                'extgwip': {
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
                'hub_iface': {
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
                    'required': True,
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
                'iface': {
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
                'ipv4-dns-server1': {
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
                'ipv4-dns-server2': {
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
                'ipv4-dns-server3': {
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
                'ipv4-end-ip': {
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
                'ipv4-exclude-range': {
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
                        }
                    },
                    'elements': 'dict'
                },
                'ipv4-netmask': {
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
                'ipv4-split-include': {
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
                'ipv4-start-ip': {
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
                'ipv4-wins-server1': {
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
                'ipv4-wins-server2': {
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
                'local-gw': {
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
                'localid': {
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
                'mode-cfg': {
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
                'mode-cfg-ip-version': {
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
                        '4',
                        '6'
                    ],
                    'type': 'str'
                },
                'net-device': {
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
                'peer': {
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
                'peergrp': {
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
                'peerid': {
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
                'peertype': {
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
                        'any',
                        'one',
                        'dialup',
                        'peer',
                        'peergrp'
                    ],
                    'type': 'str'
                },
                'protected_subnet': {
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
                        'addr': {
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
                        'seq': {
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
                        }
                    },
                    'elements': 'dict'
                },
                'public-ip': {
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
                'role': {
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
                        'hub',
                        'spoke'
                    ],
                    'type': 'str'
                },
                'route-overlap': {
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
                        'use-old',
                        'use-new',
                        'allow'
                    ],
                    'type': 'str'
                },
                'spoke-zone': {
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
                'summary_addr': {
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
                        'addr': {
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
                        'priority': {
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
                        'seq': {
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
                        }
                    },
                    'elements': 'dict'
                },
                'tunnel-search': {
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
                        'selectors',
                        'nexthop'
                    ],
                    'type': 'str'
                },
                'unity-support': {
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
                'usrgrp': {
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
                'vpn-interface-priority': {
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
                'vpn-zone': {
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
                'vpntable': {
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
                'xauthtype': {
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
                        'client',
                        'pap',
                        'chap',
                        'auto'
                    ],
                    'type': 'str'
                },
                'exchange-interface-ip': {
                    'required': False,
                    'revision': {
                        '6.2.1': True,
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
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'hub-public-ip': {
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
                'ipv4-split-exclude': {
                    'required': False,
                    'revision': {
                        '7.0.0': True,
                        '7.2.0': True,
                        '6.2.0': False,
                        '6.2.2': False,
                        '6.2.6': False,
                        '6.2.7': False,
                        '6.2.8': False,
                        '6.2.9': False,
                        '6.2.10': False,
                        '6.4.1': False,
                        '6.4.3': False,
                        '6.4.4': False,
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
                'scope member': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
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
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
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
                        'vdom': {
                            'required': False,
                            'revision': {
                                '7.2.0': True,
                                '6.2.0': False,
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
                        }
                    },
                    'elements': 'dict'
                },
                'dhcp-ra-giaddr': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
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
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
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
                'encapsulation': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
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
                        'tunnel-mode',
                        'transport-mode'
                    ],
                    'type': 'str'
                },
                'ipv4-name': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
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
                        '6.4.8': True,
                        '6.4.9': True,
                        '6.4.10': True,
                        '6.4.11': True,
                        '7.0.1': False,
                        '7.0.2': False,
                        '7.0.3': False,
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
                'l2tp': {
                    'required': False,
                    'revision': {
                        '7.2.0': True,
                        '6.2.0': False,
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
                'auto-discovery-receiver': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'auto-discovery-sender': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'network-id': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'network-overlay': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'enable',
                        'disable'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'vpnmgr_node'),
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
        fmgr.process_curd(argument_specs=module_arg_spec)
    else:
        module.fail_json(msg='MUST RUN IN HTTPAPI MODE')
    module.exit_json(meta=module.params)


if __name__ == '__main__':
    main()
