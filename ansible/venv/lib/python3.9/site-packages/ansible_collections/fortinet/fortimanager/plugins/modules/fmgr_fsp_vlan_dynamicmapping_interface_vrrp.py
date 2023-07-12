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
module: fmgr_fsp_vlan_dynamicmapping_interface_vrrp
short_description: VRRP configuration.
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
    vlan:
        description: the parameter (vlan) in requested url
        type: str
        required: true
    dynamic_mapping:
        description: the parameter (dynamic_mapping) in requested url
        type: str
        required: true
    fsp_vlan_dynamicmapping_interface_vrrp:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            accept-mode:
                type: str
                description: Enable/disable accept mode.
                choices:
                    - 'disable'
                    - 'enable'
            adv-interval:
                type: int
                description: Advertisement interval
            ignore-default-route:
                type: str
                description: Enable/disable ignoring of default route when checking destination.
                choices:
                    - 'disable'
                    - 'enable'
            preempt:
                type: str
                description: Enable/disable preempt mode.
                choices:
                    - 'disable'
                    - 'enable'
            priority:
                type: int
                description: Priority of the virtual router
            proxy-arp:
                description: description
                type: list
                elements: dict
                suboptions:
                    id:
                        type: int
                        description: ID.
                    ip:
                        type: str
                        description: Set IP addresses of proxy ARP.
            start-time:
                type: int
                description: Startup time
            status:
                type: str
                description: Enable/disable this VRRP configuration.
                choices:
                    - 'disable'
                    - 'enable'
            version:
                type: str
                description: VRRP version.
                choices:
                    - '2'
                    - '3'
            vrdst:
                description: description
                type: str
            vrdst-priority:
                type: int
                description: Priority of the virtual router when the virtual router destination becomes unreachable
            vrgrp:
                type: int
                description: VRRP group ID
            vrid:
                type: int
                description: Virtual router identifier
            vrip:
                type: str
                description: IP address of the virtual router.

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
    - name: VRRP configuration.
      fmgr_fsp_vlan_dynamicmapping_interface_vrrp:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         vlan: <your own value>
         dynamic_mapping: <your own value>
         state: <value in [present, absent]>
         fsp_vlan_dynamicmapping_interface_vrrp:
            accept-mode: <value in [disable, enable]>
            adv-interval: <value of integer>
            ignore-default-route: <value in [disable, enable]>
            preempt: <value in [disable, enable]>
            priority: <value of integer>
            proxy-arp:
              -
                  id: <value of integer>
                  ip: <value of string>
            start-time: <value of integer>
            status: <value in [disable, enable]>
            version: <value in [2, 3]>
            vrdst: <value of string>
            vrdst-priority: <value of integer>
            vrgrp: <value of integer>
            vrid: <value of integer>
            vrip: <value of string>

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
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp',
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}',
        '/pm/config/adom/{adom}/obj/fsp/vlan/{vlan}/dynamic_mapping/{dynamic_mapping}/interface/vrrp/{vrrp}'
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
        'vlan': {
            'required': True,
            'type': 'str'
        },
        'dynamic_mapping': {
            'required': True,
            'type': 'str'
        },
        'fsp_vlan_dynamicmapping_interface_vrrp': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.4.0': True
            },
            'options': {
                'accept-mode': {
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
                'adv-interval': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'ignore-default-route': {
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
                'preempt': {
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
                'priority': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'proxy-arp': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'id': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'start-time': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'status': {
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
                'version': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        '2',
                        '3'
                    ],
                    'type': 'str'
                },
                'vrdst': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'vrdst-priority': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'vrgrp': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'vrid': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'vrip': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'fsp_vlan_dynamicmapping_interface_vrrp'),
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
