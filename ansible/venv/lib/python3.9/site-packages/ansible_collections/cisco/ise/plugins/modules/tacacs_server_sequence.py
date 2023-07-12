#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tacacs_server_sequence
short_description: Resource module for TACACS Server Sequence
description:
- Manage operations create, update and delete of the resource TACACS Server Sequence.
- This API creates a TACACS server sequence.
- This API deletes a TACACS server sequence.
- This API allows the client to update a TACACS server sequence.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: TACACS Server Sequence's description.
    type: str
  id:
    description: TACACS Server Sequence's id.
    type: str
  localAccounting:
    description: LocalAccounting flag.
    type: bool
  name:
    description: TACACS Server Sequence's name.
    type: str
  prefixDelimiter:
    description: The delimiter that will be used for prefix strip.
    type: str
  prefixStrip:
    description: Define if a delimiter will be used for prefix strip.
    type: bool
  remoteAccounting:
    description: RemoteAccounting flag.
    type: bool
  serverList:
    description: The names of TACACS external servers separated by commas. The order
      of the names in the string is the order of servers that will be used during authentication.
    type: str
  suffixDelimiter:
    description: The delimiter that will be used for suffix strip.
    type: str
  suffixStrip:
    description: Define if a delimiter will be used for suffix strip.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    tacacs_server_sequence.TacacsServerSequence.create_tacacs_server_sequence,
    tacacs_server_sequence.TacacsServerSequence.delete_tacacs_server_sequence_by_id,
    tacacs_server_sequence.TacacsServerSequence.update_tacacs_server_sequence_by_id,

  - Paths used are
    post /ers/config/tacacsserversequence,
    delete /ers/config/tacacsserversequence/{id},
    put /ers/config/tacacsserversequence/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.tacacs_server_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    localAccounting: true
    name: string
    prefixDelimiter: string
    prefixStrip: true
    remoteAccounting: true
    serverList: string
    suffixDelimiter: string
    suffixStrip: true

- name: Delete by id
  cisco.ise.tacacs_server_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.tacacs_server_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    localAccounting: true
    name: string
    prefixDelimiter: string
    prefixStrip: true
    remoteAccounting: true
    serverList: string
    suffixDelimiter: string
    suffixStrip: true

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
      "serverList": "string",
      "localAccounting": true,
      "remoteAccounting": true,
      "prefixStrip": true,
      "prefixDelimiter": "string",
      "suffixStrip": true,
      "suffixDelimiter": "string",
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
