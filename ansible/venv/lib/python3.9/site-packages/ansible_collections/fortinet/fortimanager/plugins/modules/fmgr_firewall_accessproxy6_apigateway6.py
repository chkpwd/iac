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
module: fmgr_firewall_accessproxy6_apigateway6
short_description: Set IPv6 API Gateway.
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
    access-proxy6:
        description: the parameter (access-proxy6) in requested url
        type: str
        required: true
    firewall_accessproxy6_apigateway6:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            application:
                description: description
                type: str
            http-cookie-age:
                type: int
                description: Time in minutes that client web browsers should keep a cookie.
            http-cookie-domain:
                type: str
                description: Domain that HTTP cookie persistence should apply to.
            http-cookie-domain-from-host:
                type: str
                description: Enable/disable use of HTTP cookie domain from host field in HTTP.
                choices:
                    - 'disable'
                    - 'enable'
            http-cookie-generation:
                type: int
                description: Generation of HTTP cookie to be accepted.
            http-cookie-path:
                type: str
                description: Limit HTTP cookie persistence to the specified path.
            http-cookie-share:
                type: str
                description: Control sharing of cookies across API Gateway.
                choices:
                    - 'disable'
                    - 'same-ip'
            https-cookie-secure:
                type: str
                description: Enable/disable verification that inserted HTTPS cookies are secure.
                choices:
                    - 'disable'
                    - 'enable'
            id:
                type: int
                description: API Gateway ID.
            ldb-method:
                type: str
                description: Method used to distribute sessions to real servers.
                choices:
                    - 'static'
                    - 'round-robin'
                    - 'weighted'
                    - 'first-alive'
                    - 'http-host'
            persistence:
                type: str
                description: Configure how to make sure that clients connect to the same server every time they make a request that is part of the same session.
                choices:
                    - 'none'
                    - 'http-cookie'
            realservers:
                description: description
                type: list
                elements: dict
                suboptions:
                    addr-type:
                        type: str
                        description: Type of address.
                        choices:
                            - 'fqdn'
                            - 'ip'
                    address:
                        type: str
                        description: Address or address group of the real server.
                    domain:
                        type: str
                        description: Wildcard domain name of the real server.
                    health-check:
                        type: str
                        description: Enable to check the responsiveness of the real server before forwarding traffic.
                        choices:
                            - 'disable'
                            - 'enable'
                    health-check-proto:
                        type: str
                        description: Protocol of the health check monitor to use when polling to determine servers connectivity status.
                        choices:
                            - 'ping'
                            - 'http'
                            - 'tcp-connect'
                    holddown-interval:
                        type: str
                        description: Enable/disable holddown timer.
                        choices:
                            - 'disable'
                            - 'enable'
                    http-host:
                        type: str
                        description: HTTP server domain name in HTTP header.
                    id:
                        type: int
                        description: Real server ID.
                    ip:
                        type: str
                        description: IPv6 address of the real server.
                    mappedport:
                        type: str
                        description: Port for communicating with the real server.
                    port:
                        type: int
                        description: Port for communicating with the real server.
                    ssh-client-cert:
                        type: str
                        description: Set access-proxy SSH client certificate profile.
                    ssh-host-key:
                        description: description
                        type: str
                    ssh-host-key-validation:
                        type: str
                        description: Enable/disable SSH real server host key validation.
                        choices:
                            - 'disable'
                            - 'enable'
                    status:
                        type: str
                        description: Set the status of the real server to active so that it can accept traffic, or on standby or disabled so no traffic is sent.
                        choices:
                            - 'active'
                            - 'standby'
                            - 'disable'
                    type:
                        type: str
                        description: TCP forwarding server type.
                        choices:
                            - 'tcp-forwarding'
                            - 'ssh'
                    weight:
                        type: int
                        description: Weight of the real server.
                    translate-host:
                        type: str
                        description: Enable/disable translation of hostname/IP from virtual server to real server.
                        choices:
                            - 'disable'
                            - 'enable'
                    external-auth:
                        type: str
                        description: Enable/disable use of external browser as user-agent for SAML user authentication.
                        choices:
                            - 'disable'
                            - 'enable'
                    tunnel-encryption:
                        type: str
                        description: Tunnel encryption.
                        choices:
                            - 'disable'
                            - 'enable'
            saml-redirect:
                type: str
                description: Enable/disable SAML redirection after successful authentication.
                choices:
                    - 'disable'
                    - 'enable'
            saml-server:
                type: str
                description: SAML service provider configuration for VIP authentication.
            service:
                type: str
                description: Service.
                choices:
                    - 'http'
                    - 'https'
                    - 'tcp-forwarding'
                    - 'samlsp'
                    - 'web-portal'
                    - 'saas'
            ssl-algorithm:
                type: str
                description: Permitted encryption algorithms for the server side of SSL full mode sessions according to encryption strength.
                choices:
                    - 'high'
                    - 'medium'
                    - 'low'
            ssl-cipher-suites:
                description: description
                type: list
                elements: dict
                suboptions:
                    cipher:
                        type: str
                        description: Cipher suite name.
                        choices:
                            - 'TLS-RSA-WITH-RC4-128-MD5'
                            - 'TLS-RSA-WITH-RC4-128-SHA'
                            - 'TLS-RSA-WITH-DES-CBC-SHA'
                            - 'TLS-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-DHE-RSA-WITH-DES-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-RC4-128-SHA'
                            - 'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA'
                            - 'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-RSA-WITH-AES-128-GCM-SHA256'
                            - 'TLS-RSA-WITH-AES-256-GCM-SHA384'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-SEED-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384'
                            - 'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA'
                            - 'TLS-DHE-DSS-WITH-DES-CBC-SHA'
                            - 'TLS-AES-128-GCM-SHA256'
                            - 'TLS-AES-256-GCM-SHA384'
                            - 'TLS-CHACHA20-POLY1305-SHA256'
                            - 'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                    priority:
                        type: int
                        description: SSL/TLS cipher suites priority.
                    versions:
                        description: description
                        type: list
                        elements: str
                        choices:
                            - 'tls-1.0'
                            - 'tls-1.1'
                            - 'tls-1.2'
                            - 'tls-1.3'
            ssl-dh-bits:
                type: str
                description: Number of bits to use in the Diffie-Hellman exchange for RSA encryption of SSL sessions.
                choices:
                    - '768'
                    - '1024'
                    - '1536'
                    - '2048'
                    - '3072'
                    - '4096'
            ssl-max-version:
                type: str
                description: Highest SSL/TLS version acceptable from a server.
                choices:
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-min-version:
                type: str
                description: Lowest SSL/TLS version acceptable from a server.
                choices:
                    - 'tls-1.0'
                    - 'tls-1.1'
                    - 'tls-1.2'
                    - 'tls-1.3'
            ssl-vpn-web-portal:
                type: str
                description: SSL-VPN web portal.
            url-map:
                type: str
                description: URL pattern to match.
            url-map-type:
                type: str
                description: Type of url-map.
                choices:
                    - 'sub-string'
                    - 'wildcard'
                    - 'regex'
            virtual-host:
                type: str
                description: Virtual host.
            ssl-renegotiation:
                type: str
                description: Enable/disable secure renegotiation to comply with RFC 5746.
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
    - name: Set IPv6 API Gateway.
      fmgr_firewall_accessproxy6_apigateway6:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         access-proxy6: <your own value>
         state: <value in [present, absent]>
         firewall_accessproxy6_apigateway6:
            application: <value of string>
            http-cookie-age: <value of integer>
            http-cookie-domain: <value of string>
            http-cookie-domain-from-host: <value in [disable, enable]>
            http-cookie-generation: <value of integer>
            http-cookie-path: <value of string>
            http-cookie-share: <value in [disable, same-ip]>
            https-cookie-secure: <value in [disable, enable]>
            id: <value of integer>
            ldb-method: <value in [static, round-robin, weighted, ...]>
            persistence: <value in [none, http-cookie]>
            realservers:
              -
                  addr-type: <value in [fqdn, ip]>
                  address: <value of string>
                  domain: <value of string>
                  health-check: <value in [disable, enable]>
                  health-check-proto: <value in [ping, http, tcp-connect]>
                  holddown-interval: <value in [disable, enable]>
                  http-host: <value of string>
                  id: <value of integer>
                  ip: <value of string>
                  mappedport: <value of string>
                  port: <value of integer>
                  ssh-client-cert: <value of string>
                  ssh-host-key: <value of string>
                  ssh-host-key-validation: <value in [disable, enable]>
                  status: <value in [active, standby, disable]>
                  type: <value in [tcp-forwarding, ssh]>
                  weight: <value of integer>
                  translate-host: <value in [disable, enable]>
                  external-auth: <value in [disable, enable]>
                  tunnel-encryption: <value in [disable, enable]>
            saml-redirect: <value in [disable, enable]>
            saml-server: <value of string>
            service: <value in [http, https, tcp-forwarding, ...]>
            ssl-algorithm: <value in [high, medium, low]>
            ssl-cipher-suites:
              -
                  cipher: <value in [TLS-RSA-WITH-RC4-128-MD5, TLS-RSA-WITH-RC4-128-SHA, TLS-RSA-WITH-DES-CBC-SHA, ...]>
                  priority: <value of integer>
                  versions:
                    - tls-1.0
                    - tls-1.1
                    - tls-1.2
                    - tls-1.3
            ssl-dh-bits: <value in [768, 1024, 1536, ...]>
            ssl-max-version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
            ssl-min-version: <value in [tls-1.0, tls-1.1, tls-1.2, ...]>
            ssl-vpn-web-portal: <value of string>
            url-map: <value of string>
            url-map-type: <value in [sub-string, wildcard, regex]>
            virtual-host: <value of string>
            ssl-renegotiation: <value in [disable, enable]>

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
        '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6',
        '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6'
    ]

    perobject_jrpc_urls = [
        '/pm/config/global/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}',
        '/pm/config/adom/{adom}/obj/firewall/access-proxy6/{access-proxy6}/api-gateway6/{api-gateway6}'
    ]

    url_params = ['adom', 'access-proxy6']
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
        'access-proxy6': {
            'required': True,
            'type': 'str'
        },
        'firewall_accessproxy6_apigateway6': {
            'required': False,
            'type': 'dict',
            'revision': {
                '7.2.1': True,
                '7.2.2': True,
                '7.4.0': True
            },
            'options': {
                'application': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'http-cookie-age': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'http-cookie-domain': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'http-cookie-domain-from-host': {
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
                'http-cookie-generation': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'http-cookie-path': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'http-cookie-share': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'disable',
                        'same-ip'
                    ],
                    'type': 'str'
                },
                'https-cookie-secure': {
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
                'id': {
                    'required': True,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'int'
                },
                'ldb-method': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'static',
                        'round-robin',
                        'weighted',
                        'first-alive',
                        'http-host'
                    ],
                    'type': 'str'
                },
                'persistence': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'none',
                        'http-cookie'
                    ],
                    'type': 'str'
                },
                'realservers': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'addr-type': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'fqdn',
                                'ip'
                            ],
                            'type': 'str'
                        },
                        'address': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'domain': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'health-check': {
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
                        'health-check-proto': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'ping',
                                'http',
                                'tcp-connect'
                            ],
                            'type': 'str'
                        },
                        'holddown-interval': {
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
                        'http-host': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'id': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ip': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'mappedport': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'port': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'ssh-client-cert': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ssh-host-key': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'str'
                        },
                        'ssh-host-key-validation': {
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
                        'status': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'active',
                                'standby',
                                'disable'
                            ],
                            'type': 'str'
                        },
                        'type': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'tcp-forwarding',
                                'ssh'
                            ],
                            'type': 'str'
                        },
                        'weight': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'translate-host': {
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
                        'external-auth': {
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
                        'tunnel-encryption': {
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
                    },
                    'elements': 'dict'
                },
                'saml-redirect': {
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
                'saml-server': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'service': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'http',
                        'https',
                        'tcp-forwarding',
                        'samlsp',
                        'web-portal',
                        'saas'
                    ],
                    'type': 'str'
                },
                'ssl-algorithm': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'high',
                        'medium',
                        'low'
                    ],
                    'type': 'str'
                },
                'ssl-cipher-suites': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'list',
                    'options': {
                        'cipher': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'choices': [
                                'TLS-RSA-WITH-RC4-128-MD5',
                                'TLS-RSA-WITH-RC4-128-SHA',
                                'TLS-RSA-WITH-DES-CBC-SHA',
                                'TLS-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-RSA-WITH-AES-128-CBC-SHA',
                                'TLS-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-RSA-WITH-AES-256-CBC-SHA256',
                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                'TLS-RSA-WITH-SEED-CBC-SHA',
                                'TLS-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-RSA-WITH-ARIA-256-CBC-SHA384',
                                'TLS-DHE-RSA-WITH-DES-CBC-SHA',
                                'TLS-DHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-AES-256-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-DHE-RSA-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-CAMELLIA-256-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-SEED-CBC-SHA',
                                'TLS-DHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-DHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                'TLS-ECDHE-RSA-WITH-RC4-128-SHA',
                                'TLS-ECDHE-RSA-WITH-3DES-EDE-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA',
                                'TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-DHE-RSA-WITH-CHACHA20-POLY1305-SHA256',
                                'TLS-DHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-DHE-RSA-WITH-AES-256-GCM-SHA384',
                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA',
                                'TLS-DHE-DSS-WITH-AES-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-AES-128-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-AES-128-GCM-SHA256',
                                'TLS-DHE-DSS-WITH-AES-256-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-AES-256-GCM-SHA384',
                                'TLS-ECDHE-RSA-WITH-AES-128-CBC-SHA256',
                                'TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-RSA-WITH-AES-256-CBC-SHA384',
                                'TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-CBC-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA384',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384',
                                'TLS-RSA-WITH-AES-128-GCM-SHA256',
                                'TLS-RSA-WITH-AES-256-GCM-SHA384',
                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA',
                                'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA',
                                'TLS-DHE-DSS-WITH-CAMELLIA-128-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-CAMELLIA-256-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-SEED-CBC-SHA',
                                'TLS-DHE-DSS-WITH-ARIA-128-CBC-SHA256',
                                'TLS-DHE-DSS-WITH-ARIA-256-CBC-SHA384',
                                'TLS-ECDHE-RSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-RSA-WITH-ARIA-256-CBC-SHA384',
                                'TLS-ECDHE-ECDSA-WITH-ARIA-128-CBC-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-ARIA-256-CBC-SHA384',
                                'TLS-DHE-DSS-WITH-3DES-EDE-CBC-SHA',
                                'TLS-DHE-DSS-WITH-DES-CBC-SHA',
                                'TLS-AES-128-GCM-SHA256',
                                'TLS-AES-256-GCM-SHA384',
                                'TLS-CHACHA20-POLY1305-SHA256',
                                'TLS-ECDHE-ECDSA-WITH-AES-256-CBC-SHA'
                            ],
                            'type': 'str'
                        },
                        'priority': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'int'
                        },
                        'versions': {
                            'required': False,
                            'revision': {
                                '7.2.1': True,
                                '7.2.2': True,
                                '7.4.0': True
                            },
                            'type': 'list',
                            'choices': [
                                'tls-1.0',
                                'tls-1.1',
                                'tls-1.2',
                                'tls-1.3'
                            ],
                            'elements': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'ssl-dh-bits': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        '768',
                        '1024',
                        '1536',
                        '2048',
                        '3072',
                        '4096'
                    ],
                    'type': 'str'
                },
                'ssl-max-version': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'tls-1.3'
                    ],
                    'type': 'str'
                },
                'ssl-min-version': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'tls-1.0',
                        'tls-1.1',
                        'tls-1.2',
                        'tls-1.3'
                    ],
                    'type': 'str'
                },
                'ssl-vpn-web-portal': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'url-map': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'url-map-type': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'choices': [
                        'sub-string',
                        'wildcard',
                        'regex'
                    ],
                    'type': 'str'
                },
                'virtual-host': {
                    'required': False,
                    'revision': {
                        '7.2.1': True,
                        '7.2.2': True,
                        '7.4.0': True
                    },
                    'type': 'str'
                },
                'ssl-renegotiation': {
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
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'firewall_accessproxy6_apigateway6'),
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
