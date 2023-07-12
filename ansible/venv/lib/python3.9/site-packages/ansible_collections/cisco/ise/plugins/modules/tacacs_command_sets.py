#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tacacs_command_sets
short_description: Resource module for TACACS Command Sets
description:
- Manage operations create, update and delete of the resource TACACS Command Sets.
- This API creates TACACS command sets.
- This API deletes TACACS command sets.
- This API allows the client to update TACACS command sets.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  commands:
    description: TACACS Command Sets's commands.
    suboptions:
      commandList:
        description: TACACS Command Sets's commandList.
        elements: dict
        suboptions:
          arguments:
            description: TACACS Command Sets's arguments.
            type: str
          command:
            description: TACACS Command Sets's command.
            type: str
          grant:
            description: Allowed values PERMIT, DENY, DENY_ALWAYS.
            type: str
        type: list
    type: dict
  description:
    description: TACACS Command Sets's description.
    type: str
  id:
    description: TACACS Command Sets's id.
    type: str
  name:
    description: TACACS Command Sets's name.
    type: str
  permitUnmatched:
    description: PermitUnmatched flag.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    tacacs_command_sets.TacacsCommandSets.create_tacacs_command_sets,
    tacacs_command_sets.TacacsCommandSets.delete_tacacs_command_sets_by_id,
    tacacs_command_sets.TacacsCommandSets.update_tacacs_command_sets_by_id,

  - Paths used are
    post /ers/config/tacacscommandsets,
    delete /ers/config/tacacscommandsets/{id},
    put /ers/config/tacacscommandsets/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.tacacs_command_sets:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    commands:
      commandList:
      - arguments: string
        command: string
        grant: string
    description: string
    id: string
    name: string
    permitUnmatched: true

- name: Delete by id
  cisco.ise.tacacs_command_sets:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.tacacs_command_sets:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    commands:
      commandList:
      - arguments: string
        command: string
        grant: string
    description: string
    name: string
    permitUnmatched: true

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

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "UpdatedFieldsList": {
        "updatedField": [
          {
            "field": "string",
            "oldValue": "string",
            "newValue": "string"
          }
        ],
        "field": "string",
        "oldValue": "string",
        "newValue": "string"
      }
    }
"""
