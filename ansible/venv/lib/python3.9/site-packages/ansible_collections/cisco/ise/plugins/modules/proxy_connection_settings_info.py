#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: proxy_connection_settings_info
short_description: Information module for Proxy Connection Settings
description:
- Get all Proxy Connection Settings.
- The following functionalities are impacted by the proxy settings.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for proxy
  description: Complete reference of the proxy API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!system-settings-openapi
notes:
  - SDK Method used are
    proxy.Proxy.get_proxy_connection,

  - Paths used are
    get /api/v1/system-settings/proxy,

"""

EXAMPLES = r"""
- name: Get all Proxy Connection Settings
  cisco.ise.proxy_connection_settings_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

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
"""
