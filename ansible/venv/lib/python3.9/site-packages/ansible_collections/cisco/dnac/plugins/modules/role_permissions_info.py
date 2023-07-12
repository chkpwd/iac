#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: role_permissions_info
short_description: Information module for Role Permissions
description:
- Get all Role Permissions.
- Get permissions for a role from Cisco DNA Center System.
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for User and Roles GetPermissionsAPI
  description: Complete reference of the GetPermissionsAPI API.
  link: https://developer.cisco.com/docs/dna-center/#!get-permissions-api
notes:
  - SDK Method used are
    userand_roles.UserandRoles.get_permissions_ap_i,

  - Paths used are
    get /dna/system/api/v1/role/permissions,

"""

EXAMPLES = r"""
- name: Get all Role Permissions
  cisco.dnac.role_permissions_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "resource-types": [
        {
          "type": "string",
          "displayName": "string",
          "description": "string",
          "defaultPermission": "string"
        }
      ]
    }
"""
