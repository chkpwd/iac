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
module: fmgr_waf_profile
short_description: Web application firewall configuration.
description:
    - This module is able to configure a FortiManager device.
    - Examples include all parameters and values which need to be adjusted to data sources before usage.

version_added: "1.0.0"
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
    waf_profile:
        description: the top level parameters set
        required: false
        type: dict
        suboptions:
            comment:
                type: str
                description: Comment.
            extended-log:
                type: str
                description: Enable/disable extended logging.
                choices:
                    - 'disable'
                    - 'enable'
            external:
                type: str
                description: Disable/Enable external HTTP Inspection.
                choices:
                    - 'disable'
                    - 'enable'
            name:
                type: str
                description: WAF Profile name.
            url-access:
                description: Url-Access.
                type: list
                elements: dict
                suboptions:
                    access-pattern:
                        description: Access-Pattern.
                        type: list
                        elements: dict
                        suboptions:
                            id:
                                type: int
                                description: URL access pattern ID.
                            negate:
                                type: str
                                description: Enable/disable match negation.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            pattern:
                                type: str
                                description: URL pattern.
                            regex:
                                type: str
                                description: Enable/disable regular expression based pattern match.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            srcaddr:
                                type: str
                                description: Source address.
                    action:
                        type: str
                        description: Action.
                        choices:
                            - 'bypass'
                            - 'permit'
                            - 'block'
                    address:
                        type: str
                        description: Host address.
                    id:
                        type: int
                        description: URL access ID.
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
            address-list:
                description: no description
                type: dict
                required: false
                suboptions:
                    blocked-address:
                        type: str
                        description: Blocked address.
                    blocked-log:
                        type: str
                        description: Enable/disable logging on blocked addresses.
                        choices:
                            - 'disable'
                            - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
                    trusted-address:
                        type: str
                        description: Trusted address.
            constraint:
                description: no description
                type: dict
                required: false
                suboptions:
                    content-length:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Length of HTTP content in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    exception:
                        description: Exception.
                        type: list
                        elements: dict
                        suboptions:
                            address:
                                type: str
                                description: Host address.
                            content-length:
                                type: str
                                description: HTTP content length in request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            header-length:
                                type: str
                                description: HTTP header length in request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            hostname:
                                type: str
                                description: Enable/disable hostname check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            id:
                                type: int
                                description: Exception ID.
                            line-length:
                                type: str
                                description: HTTP line length in request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            malformed:
                                type: str
                                description: Enable/disable malformed HTTP request check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-cookie:
                                type: str
                                description: Maximum number of cookies in HTTP request.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-header-line:
                                type: str
                                description: Maximum number of HTTP header line.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-range-segment:
                                type: str
                                description: Maximum number of range segments in HTTP range line.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-url-param:
                                type: str
                                description: Maximum number of parameters in URL.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            method:
                                type: str
                                description: Enable/disable HTTP method check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            param-length:
                                type: str
                                description: Maximum length of parameter in URL, HTTP POST request or HTTP body.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            pattern:
                                type: str
                                description: URL pattern.
                            regex:
                                type: str
                                description: Enable/disable regular expression based pattern match.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            url-param-length:
                                type: str
                                description: Maximum length of parameter in URL.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            version:
                                type: str
                                description: Enable/disable HTTP version check.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    header-length:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Length of HTTP header in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    hostname:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    line-length:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Length of HTTP line in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    malformed:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-cookie:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-cookie:
                                type: int
                                description: Maximum number of cookies in HTTP request
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-header-line:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-header-line:
                                type: int
                                description: Maximum number HTTP header lines
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-range-segment:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-range-segment:
                                type: int
                                description: Maximum number of range segments in HTTP range line
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    max-url-param:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            max-url-param:
                                type: int
                                description: Maximum number of parameters in URL
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    method:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    param-length:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Maximum length of parameter in URL, HTTP POST request or HTTP body in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    url-param-length:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            length:
                                type: int
                                description: Maximum length of URL parameter in bytes
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    version:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Enable/disable the constraint.
                                choices:
                                    - 'disable'
                                    - 'enable'
            method:
                description: no description
                type: dict
                required: false
                suboptions:
                    default-allowed-methods:
                        description: Methods.
                        type: list
                        elements: str
                        choices:
                            - 'delete'
                            - 'get'
                            - 'head'
                            - 'options'
                            - 'post'
                            - 'put'
                            - 'trace'
                            - 'others'
                            - 'connect'
                    log:
                        type: str
                        description: Enable/disable logging.
                        choices:
                            - 'disable'
                            - 'enable'
                    method-policy:
                        description: Method-Policy.
                        type: list
                        elements: dict
                        suboptions:
                            address:
                                type: str
                                description: Host address.
                            allowed-methods:
                                description: Allowed Methods.
                                type: list
                                elements: str
                                choices:
                                    - 'delete'
                                    - 'get'
                                    - 'head'
                                    - 'options'
                                    - 'post'
                                    - 'put'
                                    - 'trace'
                                    - 'others'
                                    - 'connect'
                            id:
                                type: int
                                description: HTTP method policy ID.
                            pattern:
                                type: str
                                description: URL pattern.
                            regex:
                                type: str
                                description: Enable/disable regular expression based pattern match.
                                choices:
                                    - 'disable'
                                    - 'enable'
                    severity:
                        type: str
                        description: Severity.
                        choices:
                            - 'low'
                            - 'medium'
                            - 'high'
                    status:
                        type: str
                        description: Status.
                        choices:
                            - 'disable'
                            - 'enable'
            signature:
                description: no description
                type: dict
                required: false
                suboptions:
                    credit-card-detection-threshold:
                        type: int
                        description: The minimum number of Credit cards to detect violation.
                    custom-signature:
                        description: Custom-Signature.
                        type: list
                        elements: dict
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                                    - 'erase'
                            case-sensitivity:
                                type: str
                                description: Case sensitivity in pattern.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            direction:
                                type: str
                                description: Traffic direction.
                                choices:
                                    - 'request'
                                    - 'response'
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            name:
                                type: str
                                description: Signature name.
                            pattern:
                                type: str
                                description: Match pattern.
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Status.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            target:
                                description: Match HTTP target.
                                type: list
                                elements: str
                                choices:
                                    - 'arg'
                                    - 'arg-name'
                                    - 'req-body'
                                    - 'req-cookie'
                                    - 'req-cookie-name'
                                    - 'req-filename'
                                    - 'req-header'
                                    - 'req-header-name'
                                    - 'req-raw-uri'
                                    - 'req-uri'
                                    - 'resp-body'
                                    - 'resp-hdr'
                                    - 'resp-status'
                    disabled-signature:
                        type: str
                        description: Disabled signatures
                    disabled-sub-class:
                        type: str
                        description: Disabled signature subclasses.
                    main-class:
                        description: no description
                        type: dict
                        required: false
                        suboptions:
                            action:
                                type: str
                                description: Action.
                                choices:
                                    - 'allow'
                                    - 'block'
                                    - 'erase'
                            id:
                                type: int
                                description: Main signature class ID.
                            log:
                                type: str
                                description: Enable/disable logging.
                                choices:
                                    - 'disable'
                                    - 'enable'
                            severity:
                                type: str
                                description: Severity.
                                choices:
                                    - 'low'
                                    - 'medium'
                                    - 'high'
                            status:
                                type: str
                                description: Status.
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
    - name: Web application firewall configuration.
      fmgr_waf_profile:
         bypass_validation: False
         workspace_locking_adom: <value in [global, custom adom including root]>
         workspace_locking_timeout: 300
         rc_succeeded: [0, -2, -3, ...]
         rc_failed: [-2, -3, ...]
         adom: <your own value>
         state: <value in [present, absent]>
         waf_profile:
            comment: <value of string>
            extended-log: <value in [disable, enable]>
            external: <value in [disable, enable]>
            name: <value of string>
            url-access:
              -
                  access-pattern:
                    -
                        id: <value of integer>
                        negate: <value in [disable, enable]>
                        pattern: <value of string>
                        regex: <value in [disable, enable]>
                        srcaddr: <value of string>
                  action: <value in [bypass, permit, block]>
                  address: <value of string>
                  id: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
            address-list:
               blocked-address: <value of string>
               blocked-log: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
               trusted-address: <value of string>
            constraint:
               content-length:
                  action: <value in [allow, block]>
                  length: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               exception:
                 -
                     address: <value of string>
                     content-length: <value in [disable, enable]>
                     header-length: <value in [disable, enable]>
                     hostname: <value in [disable, enable]>
                     id: <value of integer>
                     line-length: <value in [disable, enable]>
                     malformed: <value in [disable, enable]>
                     max-cookie: <value in [disable, enable]>
                     max-header-line: <value in [disable, enable]>
                     max-range-segment: <value in [disable, enable]>
                     max-url-param: <value in [disable, enable]>
                     method: <value in [disable, enable]>
                     param-length: <value in [disable, enable]>
                     pattern: <value of string>
                     regex: <value in [disable, enable]>
                     url-param-length: <value in [disable, enable]>
                     version: <value in [disable, enable]>
               header-length:
                  action: <value in [allow, block]>
                  length: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               hostname:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               line-length:
                  action: <value in [allow, block]>
                  length: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               malformed:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               max-cookie:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  max-cookie: <value of integer>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               max-header-line:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  max-header-line: <value of integer>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               max-range-segment:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  max-range-segment: <value of integer>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               max-url-param:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  max-url-param: <value of integer>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               method:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               param-length:
                  action: <value in [allow, block]>
                  length: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               url-param-length:
                  action: <value in [allow, block]>
                  length: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
               version:
                  action: <value in [allow, block]>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
                  status: <value in [disable, enable]>
            method:
               default-allowed-methods:
                 - delete
                 - get
                 - head
                 - options
                 - post
                 - put
                 - trace
                 - others
                 - connect
               log: <value in [disable, enable]>
               method-policy:
                 -
                     address: <value of string>
                     allowed-methods:
                       - delete
                       - get
                       - head
                       - options
                       - post
                       - put
                       - trace
                       - others
                       - connect
                     id: <value of integer>
                     pattern: <value of string>
                     regex: <value in [disable, enable]>
               severity: <value in [low, medium, high]>
               status: <value in [disable, enable]>
            signature:
               credit-card-detection-threshold: <value of integer>
               custom-signature:
                 -
                     action: <value in [allow, block, erase]>
                     case-sensitivity: <value in [disable, enable]>
                     direction: <value in [request, response]>
                     log: <value in [disable, enable]>
                     name: <value of string>
                     pattern: <value of string>
                     severity: <value in [low, medium, high]>
                     status: <value in [disable, enable]>
                     target:
                       - arg
                       - arg-name
                       - req-body
                       - req-cookie
                       - req-cookie-name
                       - req-filename
                       - req-header
                       - req-header-name
                       - req-raw-uri
                       - req-uri
                       - resp-body
                       - resp-hdr
                       - resp-status
               disabled-signature: <value of string>
               disabled-sub-class: <value of string>
               main-class:
                  action: <value in [allow, block, erase]>
                  id: <value of integer>
                  log: <value in [disable, enable]>
                  severity: <value in [low, medium, high]>
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
        '/pm/config/adom/{adom}/obj/waf/profile',
        '/pm/config/global/obj/waf/profile'
    ]

    perobject_jrpc_urls = [
        '/pm/config/adom/{adom}/obj/waf/profile/{profile}',
        '/pm/config/global/obj/waf/profile/{profile}'
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
        'waf_profile': {
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
                'comment': {
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
                'extended-log': {
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
                'external': {
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
                'name': {
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
                    'type': 'str'
                },
                'url-access': {
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
                        'access-pattern': {
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
                                'negate': {
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
                                'pattern': {
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
                                'regex': {
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
                                'srcaddr': {
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
                                'bypass',
                                'permit',
                                'block'
                            ],
                            'type': 'str'
                        },
                        'address': {
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
                        'log': {
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
                        'severity': {
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
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        }
                    },
                    'elements': 'dict'
                },
                'address-list': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'blocked-address': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                        'blocked-log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'severity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'trusted-address': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                        }
                    }
                },
                'constraint': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'content-length': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'exception': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'type': 'list',
                            'options': {
                                'address': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                'content-length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'header-length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'hostname': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'line-length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'malformed': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-cookie': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-header-line': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-range-segment': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-url-param': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'method': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'param-length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'pattern': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                'regex': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'url-param-length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'version': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'header-length': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'hostname': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'line-length': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'malformed': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'max-cookie': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-cookie': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'max-header-line': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-header-line': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'max-range-segment': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-range-segment': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'max-url-param': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'max-url-param': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'method': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'param-length': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'url-param-length': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'length': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        },
                        'version': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        }
                    }
                },
                'method': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'default-allowed-methods': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'type': 'list',
                            'choices': [
                                'delete',
                                'get',
                                'head',
                                'options',
                                'post',
                                'put',
                                'trace',
                                'others',
                                'connect'
                            ],
                            'elements': 'str'
                        },
                        'log': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        },
                        'method-policy': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'type': 'list',
                            'options': {
                                'address': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                'allowed-methods': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'list',
                                    'choices': [
                                        'delete',
                                        'get',
                                        'head',
                                        'options',
                                        'post',
                                        'put',
                                        'trace',
                                        'others',
                                        'connect'
                                    ],
                                    'elements': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'pattern': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                'regex': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'severity': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'choices': [
                                'low',
                                'medium',
                                'high'
                            ],
                            'type': 'str'
                        },
                        'status': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'choices': [
                                'disable',
                                'enable'
                            ],
                            'type': 'str'
                        }
                    }
                },
                'signature': {
                    'required': False,
                    'type': 'dict',
                    'options': {
                        'credit-card-detection-threshold': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'type': 'int'
                        },
                        'custom-signature': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                            'type': 'list',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block',
                                        'erase'
                                    ],
                                    'type': 'str'
                                },
                                'case-sensitivity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'direction': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'request',
                                        'response'
                                    ],
                                    'type': 'str'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'name': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                'pattern': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'target': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'list',
                                    'choices': [
                                        'arg',
                                        'arg-name',
                                        'req-body',
                                        'req-cookie',
                                        'req-cookie-name',
                                        'req-filename',
                                        'req-header',
                                        'req-header-name',
                                        'req-raw-uri',
                                        'req-uri',
                                        'resp-body',
                                        'resp-hdr',
                                        'resp-status'
                                    ],
                                    'elements': 'str'
                                }
                            },
                            'elements': 'dict'
                        },
                        'disabled-signature': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                        'disabled-sub-class': {
                            'required': False,
                            'revision': {
                                '6.4.5': True,
                                '7.0.0': True,
                                '7.2.0': True,
                                '6.2.0': False,
                                '6.2.2': False,
                                '6.2.6': False,
                                '6.2.7': False,
                                '6.2.8': True,
                                '6.2.9': True,
                                '6.2.10': True,
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
                        'main-class': {
                            'required': False,
                            'type': 'dict',
                            'options': {
                                'action': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'allow',
                                        'block',
                                        'erase'
                                    ],
                                    'type': 'str'
                                },
                                'id': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'type': 'int'
                                },
                                'log': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                },
                                'severity': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'low',
                                        'medium',
                                        'high'
                                    ],
                                    'type': 'str'
                                },
                                'status': {
                                    'required': False,
                                    'revision': {
                                        '6.4.5': True,
                                        '7.0.0': True,
                                        '7.2.0': True,
                                        '6.2.0': False,
                                        '6.2.2': False,
                                        '6.2.6': False,
                                        '6.2.7': False,
                                        '6.2.8': True,
                                        '6.2.9': True,
                                        '6.2.10': True,
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
                                    'choices': [
                                        'disable',
                                        'enable'
                                    ],
                                    'type': 'str'
                                }
                            }
                        }
                    }
                }
            }

        }
    }

    params_validation_blob = []
    check_galaxy_version(module_arg_spec)
    module = AnsibleModule(argument_spec=check_parameter_bypass(module_arg_spec, 'waf_profile'),
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
