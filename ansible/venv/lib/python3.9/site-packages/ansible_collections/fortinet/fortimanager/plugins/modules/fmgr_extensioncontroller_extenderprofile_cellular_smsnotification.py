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
module: fmgr_extensioncontroller_extenderprofile_cellular_smsnotification
short_description: FortiExtender cellular SMS notification configuration.
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
    extender-profile:
        description: the parameter (extender-profile) in requested url
        type: str
        required: true
    extensioncontroller_extenderprofile_cellular_smsnotification:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            alert:
                description: no description
                type: dict
                required: false
                suboptions:
                    data-exhausted:
                        type: str
                        description: Display string when data exhausted.
                    fgt-backup-mode-switch:
                        type: str
                        description: Display string when FortiGate backup mode switched.
                    low-signal-strength:
                        type: str
                        description: Display string when signal strength is low.
                    mode-switch:
                        type: str
                        description: Display string when mode is switched.
                    os-image-fallback:
                        type: str
                        description: Display string when falling back to a previous OS image.
                    session-disconnect:
                        type: str
                        description: Display string when session disconnected.
                    system-reboot:
                        type: str
                        description: Display string when system rebooted.
            receiver:
                description: description
                type: list
                elements: dict
                suboptions:
                    alert:
                        description: description
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
                        type: str
                        description: FortiExtender SMS notification receiver name.
                    phone-number:
                        type: str
                        description: Receiver phone number.
                    status:
                        type: str
                        description: SMS notification receiver status.
                        choices:
                            - 'disable'
                            - 'enable'
            status:
                type: str
                description: FortiExtender SMS notification status.
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
    - name: FortiExtender cellular SMS notification configuration.
      fmgr_extensioncontroller_extenderprofile_cellular_smsnotification:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         extender-profile: <your own value>
         extensioncontroller_extenderprofile_cellular_smsnotification:
            alert:
               data-exhausted: <value of string>
               fgt-backup-mode-switch: <value of string>
               low-signal-strength: <value of string>
               mode-switch: <value of string>
               os-image-fallback: <value of string>
               session-disconnect: <value of string>
               system-reboot: <value of string>
            receiver:
              -
                  alert:
                    - system-reboot
                    - data-exhausted
                    - session-disconnect
                    - low-signal-strength
                    - mode-switch
                    - os-image-fallback
                    - fgt-backup-mode-switch
                  name: <value of string>
                  phone-number: <value of string>
                  status: <value in [disable, enable]>
            status: <value in [disable, enable]>

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
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification',
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/{sms-notification}',
        '/pm/config/adom/{adom}/obj/extension-controller/extender-profile/{extender-profile}/cellular/sms-notification/{sms-notification}'
    ]

    url_params = ['adom', 'extender-profile']
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
        'extender-profile': {
            'required': True,
            'type': 'str'
        },
        'extensioncontroller_extenderprofile_cellular_smsnotification': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'options': {
                'alert': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'data-exhausted': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'fgt-backup-mode-switch': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'low-signal-strength': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'mode-switch': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'os-image-fallback': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'session-disconnect': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'system-reboot': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        }
                    }
                },
                'receiver': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'alert': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'system-reboot',
                                'data-exhausted',
                                'session-disconnect',
                                'low-signal-strength',
                                'mode-switch',
                                'os-image-fallback',
                                'fgt-backup-mode-switch'
                            ],
                            'elements': 'str'
                        },
                        'name': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'phone-number': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'status': {
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
                        }
                    },
                    'elements': 'dict'
                },
                'status': {
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
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'extensioncontroller_extenderprofile_cellular_smsnotification'),
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
