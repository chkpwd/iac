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
module: fmgr_ips_baseline_sensor
short_description: Configure IPS sensor.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "2.2.0"
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
    ips_baseline_sensor:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            block-malicious-url:
                type: str
                description: Enable/disable malicious URL blocking.
                choices:
                    - 'disable'
                    - 'enable'
            comment:
                type: str
                description: Comment.
            entries:
                description: description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description: Action taken with traffic in which signatures are detected.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                            - 'default'
                    application:
                        description: description
                        type: str
                    cve:
                        description: description
                        type: str
                    exempt-ip:
                        description: description
                        type: list
                        elements: dict
                        suboptions:
                            dst-ip:
                                type: str
                                description: Destination IP address and netmask.
                            id:
                                type: int
                                description: Exempt IP ID.
                            src-ip:
                                type: str
                                description: Source IP address and netmask.
                    id:
                        type: int
                        description: Rule ID in IPS database
                    location:
                        description: description
                        type: str
                    log:
                        type: str
                        description: Enable/disable logging of signatures included in filter.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-attack-context:
                        type: str
                        description: Enable/disable logging of attack context
                        choices:
                            - 'disable'
                            - 'enable'
                    log-packet:
                        type: str
                        description: Enable/disable packet logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    os:
                        description: description
                        type: str
                    protocol:
                        description: description
                        type: str
                    quarantine:
                        type: str
                        description: Quarantine method.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine-expiry:
                        type: str
                        description: Duration of quarantine.
                    quarantine-log:
                        type: str
                        description: Enable/disable quarantine logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    rate-count:
                        type: int
                        description: Count of the rate.
                    rate-duration:
                        type: int
                        description: Duration
                    rate-mode:
                        type: str
                        description: Rate limit mode.
                        choices:
                            - 'periodical'
                            - 'continuous'
                    rate-track:
                        type: str
                        description: Track the packet protocol field.
                        choices:
                            - 'none'
                            - 'src-ip'
                            - 'dest-ip'
                            - 'dhcp-client-mac'
                            - 'dns-domain'
                    rule:
                        type: str
                        description: Identifies the predefined or custom IPS signatures to add to the sensor.
                    severity:
                        description: description
                        type: str
                    status:
                        type: str
                        description: Status of the signatures included in filter.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    tags:
                        type: str
                        description: no description
            extended-log:
                type: str
                description: Enable/disable extended logging.
                choices:
                    - 'disable'
                    - 'enable'
            filter:
                description: description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description: Action of selected rules.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'default'
                            - 'reset'
                    application:
                        description: description
                        type: str
                    application(real):
                        type: str
                        description: no description
                    location:
                        description: description
                        type: str
                    location(real):
                        type: str
                        description: no description
                    log:
                        type: str
                        description: Enable/disable logging of selected rules.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    log-packet:
                        type: str
                        description: Enable/disable packet logging of selected rules.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
                    name:
                        type: str
                        description: Filter name.
                    os:
                        description: description
                        type: str
                    os(real):
                        type: str
                        description: no description
                    protocol:
                        description: description
                        type: str
                    protocol(real):
                        type: str
                        description: no description
                    quarantine:
                        type: str
                        description: Quarantine IP or interface.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine-expiry:
                        type: int
                        description: Duration of quarantine in minute.
                    quarantine-log:
                        type: str
                        description: Enable/disable logging of selected quarantine.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        description: description
                        type: str
                    severity(real):
                        type: str
                        description: no description
                    status:
                        type: str
                        description: Selected rules status.
                        choices:
                            - 'disable'
                            - 'enable'
                            - 'default'
            log:
                type: str
                description: no description
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: Sensor name.
            override:
                description: description
                type: list
                elements: dict
                suboptions:
                    action:
                        type: str
                        description: Action of override rule.
                        choices:
                            - 'pass'
                            - 'block'
                            - 'reset'
                    exempt-ip:
                        description: description
                        type: list
                        elements: dict
                        suboptions:
                            dst-ip:
                                type: str
                                description: Destination IP address and netmask.
                            id:
                                type: int
                                description: Exempt IP ID.
                            src-ip:
                                type: str
                                description: Source IP address and netmask.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    log-packet:
                        type: str
                        description: Enable/disable packet logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    quarantine:
                        type: str
                        description: Quarantine IP or interface.
                        choices:
                            - 'none'
                            - 'attacker'
                            - 'both'
                            - 'interface'
                    quarantine-expiry:
                        type: int
                        description: Duration of quarantine in minute.
                    quarantine-log:
                        type: str
                        description: Enable/disable logging of selected quarantine.
                        choices:
                            - 'disable'
                            - 'enable'
                    rule-id:
                        type: int
                        description: Override rule ID.
                    status:
                        type: str
                        description: Enable/disable status of override rule.
                        choices:
                            - 'disable'
                            - 'enable'
            replacemsg-group:
                type: str
                description: Replacement message group.
            scan-botnet-connections:
                type: str
                description: Block or monitor connections to Botnet servers, or disable Botnet scanning.
                choices:
                    - 'disable'
                    - 'block'
                    - 'monitor'

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
    - name: Configure IPS sensor.
      fmgr_ips_baseline_sensor:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         ips_baseline_sensor:
            block-malicious-url: <value in [disable, enable]>
            comment: <value of string>
            entries:
              -
                  action: <value in [pass, block, reset, ...]>
                  application: <value of string>
                  cve: <value of string>
                  exempt-ip:
                    -
                        dst-ip: <value of string>
                        id: <value of integer>
                        src-ip: <value of string>
                  id: <value of integer>
                  location: <value of string>
                  log: <value in [disable, enable]>
                  log-attack-context: <value in [disable, enable]>
                  log-packet: <value in [disable, enable]>
                  os: <value of string>
                  protocol: <value of string>
                  quarantine: <value in [none, attacker, both, ...]>
                  quarantine-expiry: <value of string>
                  quarantine-log: <value in [disable, enable]>
                  rate-count: <value of integer>
                  rate-duration: <value of integer>
                  rate-mode: <value in [periodical, continuous]>
                  rate-track: <value in [none, src-ip, dest-ip, ...]>
                  rule: <value of string>
                  severity: <value of string>
                  status: <value in [disable, enable, default]>
                  tags: <value of string>
            extended-log: <value in [disable, enable]>
            filter:
              -
                  action: <value in [pass, block, default, ...]>
                  application: <value of string>
                  application(real): <value of string>
                  location: <value of string>
                  location(real): <value of string>
                  log: <value in [disable, enable, default]>
                  log-packet: <value in [disable, enable, default]>
                  name: <value of string>
                  os: <value of string>
                  os(real): <value of string>
                  protocol: <value of string>
                  protocol(real): <value of string>
                  quarantine: <value in [none, attacker, both, ...]>
                  quarantine-expiry: <value of integer>
                  quarantine-log: <value in [disable, enable]>
                  severity: <value of string>
                  severity(real): <value of string>
                  status: <value in [disable, enable, default]>
            log: <value in [disable, enable]>
            name: <value of string>
            override:
              -
                  action: <value in [pass, block, reset]>
                  exempt-ip:
                    -
                        dst-ip: <value of string>
                        id: <value of integer>
                        src-ip: <value of string>
                  log: <value in [disable, enable]>
                  log-packet: <value in [disable, enable]>
                  quarantine: <value in [none, attacker, both, ...]>
                  quarantine-expiry: <value of integer>
                  quarantine-log: <value in [disable, enable]>
                  rule-id: <value of integer>
                  status: <value in [disable, enable]>
            replacemsg-group: <value of string>
            scan-botnet-connections: <value in [disable, block, monitor]>

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
        '/pm/config/global/obj/ips/baseline/sensor',
        '/pm/config/adom/{adom}/obj/ips/baseline/sensor'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/ips/baseline/sensor/{sensor}',
        '/pm/config/adom/{adom}/obj/ips/baseline/sensor/{sensor}'
    ]

    url_params = ['adom']
    module_primary_key = 'name'
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
        'ips_baseline_sensor': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.0.1': True,
                '7.0.2': True
            },
            'options': {
                'block-malicious-url': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'comment': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
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
                'entries': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'pass',
                                'block',
                                'reset',
                                'default'
                            ],
                            'type': 'str'
                        },
                        'application': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'cve': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'exempt-ip': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'list',
                            'options': {
                                'dst-ip': {
                                    'required': False,
                                    'revision': {
                                        '7.0.1': True,
                                        '7.0.2': True,
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
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': False,
                                        '7.0.4': False,
                                        '7.0.5': False,
                                        '7.0.6': False,
                                        '7.0.7': False,
                                        '7.2.1': False,
                                        '7.2.2': False,
                                        '7.4.0': False
                                    },
                                    'type': 'int'
                                },
                                'src-ip': {
                                    'required': False,
                                    'revision': {
                                        '7.0.1': True,
                                        '7.0.2': True,
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
                                }
                            },
                            'elements': 'dict'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'location': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'log': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'log-attack-context': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'log-packet': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'os': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'protocol': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'none',
                                'attacker',
                                'both',
                                'interface'
                            ],
                            'type': 'str'
                        },
                        'quarantine-expiry': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'quarantine-log': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'rate-count': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'rate-duration': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'rate-mode': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'periodical',
                                'continuous'
                            ],
                            'type': 'str'
                        },
                        'rate-track': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'none',
                                'src-ip',
                                'dest-ip',
                                'dhcp-client-mac',
                                'dns-domain'
                            ],
                            'type': 'str'
                        },
                        'rule': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'severity': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'status': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'default'
                            ],
                            'type': 'str'
                        },
                        'tags': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        }
                    },
                    'elements': 'dict'
                },
                'extended-log': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'filter': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'pass',
                                'block',
                                'default',
                                'reset'
                            ],
                            'type': 'str'
                        },
                        'application': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'application(real)': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'location': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'location(real)': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'log': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'default'
                            ],
                            'type': 'str'
                        },
                        'log-packet': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'default'
                            ],
                            'type': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'os': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'os(real)': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'protocol': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'protocol(real)': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'none',
                                'attacker',
                                'both',
                                'interface'
                            ],
                            'type': 'str'
                        },
                        'quarantine-expiry': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'quarantine-log': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'severity(real)': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
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
                        'status': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable',
                                'default'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'log': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'disable',
                        'enable'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
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
                'override': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'type': 'list',
                    'options': {
                        'action': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'pass',
                                'block',
                                'reset'
                            ],
                            'type': 'str'
                        },
                        'exempt-ip': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'list',
                            'options': {
                                'dst-ip': {
                                    'required': False,
                                    'revision': {
                                        '7.0.1': True,
                                        '7.0.2': True,
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
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '7.0.1': True,
                                        '7.0.2': True,
                                        '7.0.3': False,
                                        '7.0.4': False,
                                        '7.0.5': False,
                                        '7.0.6': False,
                                        '7.0.7': False,
                                        '7.2.1': False,
                                        '7.2.2': False,
                                        '7.4.0': False
                                    },
                                    'type': 'int'
                                },
                                'src-ip': {
                                    'required': False,
                                    'revision': {
                                        '7.0.1': True,
                                        '7.0.2': True,
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
                                }
                            },
                            'elements': 'dict'
                        },
                        'log': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'log-packet': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'quarantine': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'none',
                                'attacker',
                                'both',
                                'interface'
                            ],
                            'type': 'str'
                        },
                        'quarantine-expiry': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'quarantine-log': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'rule-id': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'type': 'int'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '7.0.1': True,
                                '7.0.2': True,
                                '7.0.3': False,
                                '7.0.4': False,
                                '7.0.5': False,
                                '7.0.6': False,
                                '7.0.7': False,
                                '7.2.1': False,
                                '7.2.2': False,
                                '7.4.0': False
                            },
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'replacemsg-group': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
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
                'scan-botnet-connections': {
                    'required': False,
                    'revision': {
                        '7.0.1': True,
                        '7.0.2': True,
                        '7.0.3': False,
                        '7.0.4': False,
                        '7.0.5': False,
                        '7.0.6': False,
                        '7.0.7': False,
                        '7.2.1': False,
                        '7.2.2': False,
                        '7.4.0': False
                    },
                    'choices': [
                        'disable',
                        'block',
                        'monitor'
                    ],
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'ips_baseline_sensor'),
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
