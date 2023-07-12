#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_dictionary_attributes_authorization_info
short_description: Information module for Device Administration Dictionary Attributes Authorization
description:
- Get all Device Administration Dictionary Attributes Authorization.
- Network Access - Returns list of dictionary attributes for authorization.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Dictionary Attributes List
  description: Complete reference of the Device Administration - Dictionary Attributes List API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_dictionary_attributes_list.DeviceAdministrationDictionaryAttributesList.get_device_admin_dictionaries_authorization,

  - Paths used are
    get /device-admin/dictionaries/authorization,

"""

EXAMPLES = r"""
- name: Get all Device Administration Dictionary Attributes Authorization
  cisco.ise.device_administration_dictionary_attributes_authorization_info:
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
        "allowedValues": [
          {
            "isDefault": true,
            "key": "string",
            "value": "string"
          }
        ],
        "dataType": "string",
        "description": "string",
        "dictionaryName": "string",
        "directionType": "string",
        "id": "string",
        "internalName": "string",
        "name": "string"
      }
    ]
"""
