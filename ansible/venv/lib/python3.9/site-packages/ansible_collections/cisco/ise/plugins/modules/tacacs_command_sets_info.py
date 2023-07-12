#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tacacs_command_sets_info
short_description: Information module for TACACS Command Sets
description:
- Get all TACACS Command Sets.
- Get TACACS Command Sets by id.
- Get TACACS Command Sets by name.
- This API allows the client to get TACACS command sets by ID.
- This API allows the client to get TACACS command sets by name.
- This API allows the client to get all the TACACS command sets.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  name:
    description:
    - Name path parameter.
    type: str
  id:
    description:
    - Id path parameter.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    tacacs_command_sets.TacacsCommandSets.get_tacacs_command_sets_by_id,
    tacacs_command_sets.TacacsCommandSets.get_tacacs_command_sets_by_name,
    tacacs_command_sets.TacacsCommandSets.get_tacacs_command_sets_generator,

  - Paths used are
    get /ers/config/tacacscommandsets,
    get /ers/config/tacacscommandsets/name/{name},
    get /ers/config/tacacscommandsets/{id},

"""

EXAMPLES = r"""
- name: Get all TACACS Command Sets
  cisco.ise.tacacs_command_sets_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get TACACS Command Sets by id
  cisco.ise.tacacs_command_sets_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get TACACS Command Sets by name
  cisco.ise.tacacs_command_sets_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "permitUnmatched": true,
      "commands": {
        "commandList": [
          {
            "grant": "string",
            "command": "string",
            "arguments": "string"
          }
        ]
      },
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "name": "string",
        "description": "string",
        "permitUnmatched": true,
        "commands": {
          "commandList": [
            {
              "grant": "string",
              "command": "string",
              "arguments": "string"
            }
          ]
        },
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""
