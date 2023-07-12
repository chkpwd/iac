#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_dictionary_attribute_info
short_description: Information module for Network Access Dictionary Attribute
description:
- Get all Network Access Dictionary Attribute.
- Get Network Access Dictionary Attribute by name.
- Get a Dictionary Attribute.
- Returns a list of Dictionary Attributes for an existing Dictionary.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  dictionaryName:
    description:
    - DictionaryName path parameter. The name of the dictionary the dictionary attribute belongs to.
    type: str
  name:
    description:
    - Name path parameter. The dictionary attribute name.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Network Access - Dictionary Attribute
  description: Complete reference of the Network Access - Dictionary Attribute API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_dictionary_attribute.NetworkAccessDictionaryAttribute.get_network_access_dictionary_attribute_by_name,
    network_access_dictionary_attribute.NetworkAccessDictionaryAttribute.get_network_access_dictionary_attributes_by_dictionary_name,

  - Paths used are
    get /network-access/dictionaries/{dictionaryName}/attribute,
    get /network-access/dictionaries/{dictionaryName}/attribute/{name},

"""

EXAMPLES = r"""
- name: Get all Network Access Dictionary Attribute
  cisco.ise.network_access_dictionary_attribute_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    dictionaryName: string
  register: result

- name: Get Network Access Dictionary Attribute by name
  cisco.ise.network_access_dictionary_attribute_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
    dictionaryName: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
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
"""
