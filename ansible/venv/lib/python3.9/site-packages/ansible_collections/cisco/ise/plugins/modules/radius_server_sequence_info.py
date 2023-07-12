#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: radius_server_sequence_info
short_description: Information module for RADIUS Server Sequence
description:
- Get all RADIUS Server Sequence.
- Get RADIUS Server Sequence by id.
- This API allows the client to get a RADIUS server sequence by ID.
- This API allows the client to get all the RADIUS server sequences.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
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
    radius_server_sequence.RadiusServerSequence.get_radius_server_sequence_by_id,
    radius_server_sequence.RadiusServerSequence.get_radius_server_sequence_generator,

  - Paths used are
    get /ers/config/radiusserversequence,
    get /ers/config/radiusserversequence/{id},

"""

EXAMPLES = r"""
- name: Get all RADIUS Server Sequence
  cisco.ise.radius_server_sequence_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get RADIUS Server Sequence by id
  cisco.ise.radius_server_sequence_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
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
      "stripPrefix": true,
      "stripSuffix": true,
      "prefixSeparator": "string",
      "suffixSeparator": "string",
      "remoteAccounting": true,
      "localAccounting": true,
      "useAttrSetOnRequest": true,
      "useAttrSetBeforeAcc": true,
      "continueAuthorzPolicy": true,
      "RadiusServerList": [
        "string"
      ],
      "OnRequestAttrManipulatorList": [
        {
          "action": "string",
          "dictionaryName": "string",
          "attributeName": "string",
          "value": "string",
          "changedVal": "string"
        }
      ],
      "BeforeAcceptAttrManipulatorsList": [
        {
          "action": "string",
          "dictionaryName": "string",
          "attributeName": "string",
          "value": "string",
          "changedVal": "string"
        }
      ],
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
        "stripPrefix": true,
        "stripSuffix": true,
        "prefixSeparator": "string",
        "suffixSeparator": "string",
        "remoteAccounting": true,
        "localAccounting": true,
        "useAttrSetOnRequest": true,
        "useAttrSetBeforeAcc": true,
        "continueAuthorzPolicy": true,
        "RadiusServerList": [
          "string"
        ],
        "OnRequestAttrManipulatorList": [
          {
            "action": "string",
            "dictionaryName": "string",
            "attributeName": "string",
            "value": "string",
            "changedVal": "string"
          }
        ],
        "BeforeAcceptAttrManipulatorsList": [
          {
            "action": "string",
            "dictionaryName": "string",
            "attributeName": "string",
            "value": "string",
            "changedVal": "string"
          }
        ],
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""
