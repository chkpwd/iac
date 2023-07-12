#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_dictionary
short_description: Resource module for Network Access Dictionary
description:
- Manage operations create, update and delete of the resource Network Access Dictionary.
- Network Access - Create a new Dictionary.
- Network Access - Delete a Dictionary.
- Network Access - Update a Dictionary.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: The description of the Dictionary.
    type: str
  dictionaryAttrType:
    description: The dictionary attribute type.
    type: str
  id:
    description: Identifier for the dictionary.
    type: str
  link:
    description: Network Access Dictionary's link.
    suboptions:
      href:
        description: Network Access Dictionary's href.
        type: str
      rel:
        description: Network Access Dictionary's rel.
        type: str
      type:
        description: Network Access Dictionary's type.
        type: str
    type: dict
  name:
    description: The dictionary name.
    type: str
  version:
    description: The dictionary version.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Network Access - Dictionary
  description: Complete reference of the Network Access - Dictionary API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_dictionary.NetworkAccessDictionary.create_network_access_dictionaries,
    network_access_dictionary.NetworkAccessDictionary.delete_network_access_dictionary_by_name,
    network_access_dictionary.NetworkAccessDictionary.update_network_access_dictionary_by_name,

  - Paths used are
    post /network-access/dictionaries,
    delete /network-access/dictionaries/{name},
    put /network-access/dictionaries/{name},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.network_access_dictionary:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    dictionaryAttrType: string
    id: string
    link:
      href: string
      rel: string
      type: string
    name: string
    version: string

- name: Update by name
  cisco.ise.network_access_dictionary:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    dictionaryAttrType: string
    id: string
    link:
      href: string
      rel: string
      type: string
    name: string
    version: string

- name: Delete by name
  cisco.ise.network_access_dictionary:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    name: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "description": "string",
      "dictionaryAttrType": "string",
      "id": "string",
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "name": "string",
      "version": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "response": {
        "description": "string",
        "dictionaryAttrType": "string",
        "id": "string",
        "link": {
          "href": "string",
          "rel": "string",
          "type": "string"
        },
        "name": "string",
        "version": "string"
      },
      "version": "string"
    }
"""
