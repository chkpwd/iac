#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_identity_stores_info
short_description: Information module for Device Administration Identity Stores
description:
- Get all Device Administration Identity Stores.
- Device Admin - Return list of identity stores for authentication.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Identity Stores
  description: Complete reference of the Device Administration - Identity Stores API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_identity_stores.DeviceAdministrationIdentityStores.get_device_admin_identity_stores,

  - Paths used are
    get /device-admin/identity-stores,

"""

EXAMPLES = r"""
- name: Get all Device Administration Identity Stores
  cisco.ise.device_administration_identity_stores_info:
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
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "name": "string"
      }
    ]
"""
