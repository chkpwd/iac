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
module: fmgr_cloud_orchestawstemplate_autoscalenewvpc
short_description: no description
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
    cloud_orchestawstemplate_autoscalenewvpc:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            availability-zones:
                type: str
                description: no description
            custom-asset-container:
                type: str
                description: no description
            custom-asset-directory:
                type: str
                description: no description
            custom-identifier:
                type: str
                description: no description
            faz-autoscale-admin-password:
                description: description
                type: str
            faz-autoscale-admin-username:
                type: str
                description: no description
            faz-custom-private-ipaddress:
                type: str
                description: no description
            faz-instance-type:
                type: str
                description: no description
                choices:
                    - 'h1.2xlarge'
                    - 'h1.4xlarge'
                    - 'h1.8xlarge'
                    - 'm5.large'
                    - 'm5.xlarge'
                    - 'm5.2xlarge'
                    - 'm5.4xlarge'
                    - 'm5.12xlarge'
                    - 't2.medium'
                    - 't2.large'
                    - 't2.xlarge'
            faz-integration-options:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'yes'
            faz-version:
                type: str
                description: no description
            fgt-admin-cidr:
                type: str
                description: no description
            fgt-admin-port:
                type: int
                description: no description
            fgt-instance-type:
                type: str
                description: no description
                choices:
                    - 't2.small'
                    - 'c5.large'
                    - 'c5.xlarge'
                    - 'c5.2xlarge'
                    - 'c5.4xlarge'
                    - 'c5.9xlarge'
            fgt-psk-secret:
                type: str
                description: no description
            fgtasg-cool-down:
                type: int
                description: no description
            fgtasg-desired-capacity-byol:
                type: int
                description: no description
            fgtasg-desired-capacity-payg:
                type: int
                description: no description
            fgtasg-health-check-grace-period:
                type: int
                description: no description
            fgtasg-max-size-byol:
                type: int
                description: no description
            fgtasg-max-size-payg:
                type: int
                description: no description
            fgtasg-min-size-byol:
                type: int
                description: no description
            fgtasg-min-size-payg:
                type: int
                description: no description
            fgtasg-scale-in-threshold:
                type: int
                description: no description
            fgtasg-scale-out-threshold:
                type: int
                description: no description
            fos-version:
                type: str
                description: no description
            get-license-grace-period:
                type: int
                description: no description
            heartbeat-delay-allowance:
                type: int
                description: no description
            heartbeat-interval:
                type: int
                description: no description
            heartbeat-loss-count:
                type: int
                description: no description
            internal-balancer-dns-name:
                type: str
                description: no description
            internal-balancing-options:
                type: str
                description: no description
                choices:
                    - 'add a new internal load balancer'
                    - 'use a load balancer specified below'
                    - 'do not need one'
            internal-target-group-health-check-path:
                type: str
                description: no description
            key-pair-name:
                type: str
                description: no description
            lifecycle-hook-timeout:
                type: int
                description: no description
            loadbalancing-health-check-threshold:
                type: int
                description: no description
            loadbalancing-traffic-port:
                type: int
                description: no description
            loadbalancing-traffic-protocol:
                type: str
                description: no description
                choices:
                    - 'HTTPS'
                    - 'HTTP'
                    - 'TCP'
            name:
                type: str
                description: no description
            notification-email:
                type: str
                description: no description
            primary-election-timeout:
                type: int
                description: no description
            private-subnet1-cidr:
                type: str
                description: no description
            private-subnet2-cidr:
                type: str
                description: no description
            public-subnet1-cidr:
                type: str
                description: no description
            public-subnet2-cidr:
                type: str
                description: no description
            resource-tag-prefix:
                type: str
                description: no description
            s3-bucket-name:
                type: str
                description: no description
            s3-key-prefix:
                type: str
                description: no description
            sync-recovery-count:
                type: int
                description: no description
            terminate-unhealthy-vm:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'yes'
            use-custom-asset-location:
                type: str
                description: no description
                choices:
                    - 'no'
                    - 'yes'
            vpc-cidr:
                type: str
                description: no description

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
    - name: no description
      fmgr_cloud_orchestawstemplate_autoscalenewvpc:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         cloud_orchestawstemplate_autoscalenewvpc:
            availability-zones: <value of string>
            custom-asset-container: <value of string>
            custom-asset-directory: <value of string>
            custom-identifier: <value of string>
            faz-autoscale-admin-password: <value of string>
            faz-autoscale-admin-username: <value of string>
            faz-custom-private-ipaddress: <value of string>
            faz-instance-type: <value in [h1.2xlarge, h1.4xlarge, h1.8xlarge, ...]>
            faz-integration-options: <value in [no, yes]>
            faz-version: <value of string>
            fgt-admin-cidr: <value of string>
            fgt-admin-port: <value of integer>
            fgt-instance-type: <value in [t2.small, c5.large, c5.xlarge, ...]>
            fgt-psk-secret: <value of string>
            fgtasg-cool-down: <value of integer>
            fgtasg-desired-capacity-byol: <value of integer>
            fgtasg-desired-capacity-payg: <value of integer>
            fgtasg-health-check-grace-period: <value of integer>
            fgtasg-max-size-byol: <value of integer>
            fgtasg-max-size-payg: <value of integer>
            fgtasg-min-size-byol: <value of integer>
            fgtasg-min-size-payg: <value of integer>
            fgtasg-scale-in-threshold: <value of integer>
            fgtasg-scale-out-threshold: <value of integer>
            fos-version: <value of string>
            get-license-grace-period: <value of integer>
            heartbeat-delay-allowance: <value of integer>
            heartbeat-interval: <value of integer>
            heartbeat-loss-count: <value of integer>
            internal-balancer-dns-name: <value of string>
            internal-balancing-options: <value in [add a new internal load balancer, use a load balancer specified below, do not need one]>
            internal-target-group-health-check-path: <value of string>
            key-pair-name: <value of string>
            lifecycle-hook-timeout: <value of integer>
            loadbalancing-health-check-threshold: <value of integer>
            loadbalancing-traffic-port: <value of integer>
            loadbalancing-traffic-protocol: <value in [HTTPS, HTTP, TCP]>
            name: <value of string>
            notification-email: <value of string>
            primary-election-timeout: <value of integer>
            private-subnet1-cidr: <value of string>
            private-subnet2-cidr: <value of string>
            public-subnet1-cidr: <value of string>
            public-subnet2-cidr: <value of string>
            resource-tag-prefix: <value of string>
            s3-bucket-name: <value of string>
            s3-key-prefix: <value of string>
            sync-recovery-count: <value of integer>
            terminate-unhealthy-vm: <value in [no, yes]>
            use-custom-asset-location: <value in [no, yes]>
            vpc-cidr: <value of string>

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
        '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc',
        '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}',
        '/pm/config/adom/{adom}/obj/cloud/orchest-awstemplate/autoscale-new-vpc/{autoscale-new-vpc}'
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
        'cloud_orchestawstemplate_autoscalenewvpc': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.4.0': True
            },
            'options': {
                'availability-zones': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'custom-asset-container': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'custom-asset-directory': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'custom-identifier': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'faz-autoscale-admin-password': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'no_log': True,
                    'type': 'str'
                },
                'faz-autoscale-admin-username': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'faz-custom-private-ipaddress': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'faz-instance-type': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'h1.2xlarge',
                        'h1.4xlarge',
                        'h1.8xlarge',
                        'm5.large',
                        'm5.xlarge',
                        'm5.2xlarge',
                        'm5.4xlarge',
                        'm5.12xlarge',
                        't2.medium',
                        't2.large',
                        't2.xlarge'
                    ],
                    'type': 'str'
                },
                'faz-integration-options': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'no',
                        'yes'
                    ],
                    'type': 'str'
                },
                'faz-version': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'fgt-admin-cidr': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'fgt-admin-port': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgt-instance-type': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        't2.small',
                        'c5.large',
                        'c5.xlarge',
                        'c5.2xlarge',
                        'c5.4xlarge',
                        'c5.9xlarge'
                    ],
                    'type': 'str'
                },
                'fgt-psk-secret': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'fgtasg-cool-down': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-desired-capacity-byol': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-desired-capacity-payg': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-health-check-grace-period': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-max-size-byol': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-max-size-payg': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-min-size-byol': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-min-size-payg': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-scale-in-threshold': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fgtasg-scale-out-threshold': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'fos-version': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'get-license-grace-period': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'heartbeat-delay-allowance': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'heartbeat-interval': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'heartbeat-loss-count': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'internal-balancer-dns-name': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'internal-balancing-options': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'add a new internal load balancer',
                        'use a load balancer specified below',
                        'do not need one'
                    ],
                    'type': 'str'
                },
                'internal-target-group-health-check-path': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'key-pair-name': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'lifecycle-hook-timeout': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'loadbalancing-health-check-threshold': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'loadbalancing-traffic-port': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'loadbalancing-traffic-protocol': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'HTTPS',
                        'HTTP',
                        'TCP'
                    ],
                    'type': 'str'
                },
                'name': {
                    'required': True,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'notification-email': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'primary-election-timeout': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'private-subnet1-cidr': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'private-subnet2-cidr': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'public-subnet1-cidr': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'public-subnet2-cidr': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'resource-tag-prefix': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                's3-bucket-name': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                's3-key-prefix': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'sync-recovery-count': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'terminate-unhealthy-vm': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'no',
                        'yes'
                    ],
                    'type': 'str'
                },
                'use-custom-asset-location': {
                    'required': False,
                    'revision': {
                        '7.4.0': True
                    },
                    'choices': [
                        'no',
                        'yes'
                    ],
                    'type': 'str'
                },
                'vpc-cidr': {
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
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'cloud_orchestawstemplate_autoscalenewvpc'),
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
