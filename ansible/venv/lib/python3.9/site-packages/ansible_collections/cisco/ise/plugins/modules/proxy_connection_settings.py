#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: proxy_connection_settings
short_description: Resource module for Proxy Connection Settings
description:
- Manage operation update of the resource Proxy Connection Settings.
- The following functionalities are impacted by the proxy settings.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  bypassHosts:
    description: Bypass hosts for the proxy connection.
    type: str
  fqdn:
    description: Proxy IP address or DNS-resolvable host name.
    type: str
  password:
    description: Password for the proxy connection.
    type: str
  passwordRequired:
    description: Indicates whether password configuration is required for Proxy.
    type: bool
  port:
    description: Port for proxy connection. Should be between 1 and 65535.
    type: int
  userName:
    description: User name for the proxy connection.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for proxy
  description: Complete reference of the proxy API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!system-settings-openapi
notes:
  - SDK Method used are
    proxy.Proxy.update_proxy_connection,

  - Paths used are
    put /api/v1/system-settings/proxy,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.proxy_connection_settings:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    bypassHosts: string
    fqdn: string
    password: string
    passwordRequired: true
    port: 0
    userName: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "bypassHosts": "string",
      "fqdn": "string",
      "password": "string",
      "passwordRequired": true,
      "port": 0,
      "userName": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "bypassHosts": "string",
        "fqdn": "string",
        "password": "string",
        "passwordRequired": true,
        "port": 0,
        "userName": "string"
      },
      "version": "string"
    }
"""
