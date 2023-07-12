#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: radius_server_sequence
short_description: Resource module for RADIUS Server Sequence
description:
- Manage operations create, update and delete of the resource RADIUS Server Sequence.
- This API creates a RADIUS server sequence.
- This API deletes a RADIUS server sequence.
- This API allows the client to update a RADIUS server sequence.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  BeforeAcceptAttrManipulatorsList:
    description: The beforeAcceptAttrManipulators is required only if useAttrSetBeforeAcc
      is true.
    elements: dict
    suboptions:
      action:
        description: Allowed Values - ADD, - UPDATE, - REMOVE, - REMOVEANY.
        type: str
      attributeName:
        description: RADIUS Server Sequence's attributeName.
        type: str
      changedVal:
        description: The changedVal is required only if the action equals to 'UPDATE'.
        type: str
      dictionaryName:
        description: RADIUS Server Sequence's dictionaryName.
        type: str
      value:
        description: RADIUS Server Sequence's value.
        type: str
    type: list
  OnRequestAttrManipulatorList:
    description: The onRequestAttrManipulators is required only if useAttrSetOnRequest
      is true.
    elements: dict
    suboptions:
      action:
        description: Allowed Values - ADD, - UPDATE, - REMOVE, - REMOVEANY.
        type: str
      attributeName:
        description: RADIUS Server Sequence's attributeName.
        type: str
      changedVal:
        description: The changedVal is required only if the action equals to 'UPDATE'.
        type: str
      dictionaryName:
        description: RADIUS Server Sequence's dictionaryName.
        type: str
      value:
        description: RADIUS Server Sequence's value.
        type: str
    type: list
  RADIUSServerList:
    description: RADIUS Server Sequence's RADIUSServerList.
    elements: str
    type: list
  continueAuthorzPolicy:
    description: ContinueAuthorzPolicy flag.
    type: bool
  description:
    description: RADIUS Server Sequence's description.
    type: str
  id:
    description: RADIUS Server Sequence's id.
    type: str
  localAccounting:
    description: LocalAccounting flag.
    type: bool
  name:
    description: RADIUS Server Sequence's name.
    type: str
  prefixSeparator:
    description: The prefixSeparator is required only if stripPrefix is true. The maximum
      length is 1 character.
    type: str
  remoteAccounting:
    description: RemoteAccounting flag.
    type: bool
  stripPrefix:
    description: StripPrefix flag.
    type: bool
  stripSuffix:
    description: StripSuffix flag.
    type: bool
  suffixSeparator:
    description: The suffixSeparator is required only if stripSuffix is true. The maximum
      length is 1 character.
    type: str
  useAttrSetBeforeAcc:
    description: UseAttrSetBeforeAcc flag.
    type: bool
  useAttrSetOnRequest:
    description: UseAttrSetOnRequest flag.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    radius_server_sequence.RadiusServerSequence.create_radius_server_sequence,
    radius_server_sequence.RadiusServerSequence.delete_radius_server_sequence_by_id,
    radius_server_sequence.RadiusServerSequence.update_radius_server_sequence_by_id,

  - Paths used are
    post /ers/config/radiusserversequence,
    delete /ers/config/radiusserversequence/{id},
    put /ers/config/radiusserversequence/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.radius_server_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    BeforeAcceptAttrManipulatorsList:
    - action: string
      attributeName: string
      changedVal: string
      dictionaryName: string
      value: string
    OnRequestAttrManipulatorList:
    - action: string
      attributeName: string
      changedVal: string
      dictionaryName: string
      value: string
    RadiusServerList:
    - string
    continueAuthorzPolicy: true
    description: string
    id: string
    localAccounting: true
    name: string
    prefixSeparator: string
    remoteAccounting: true
    stripPrefix: true
    stripSuffix: true
    suffixSeparator: string
    useAttrSetBeforeAcc: true
    useAttrSetOnRequest: true

- name: Delete by id
  cisco.ise.radius_server_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.radius_server_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    BeforeAcceptAttrManipulatorsList:
    - action: string
      attributeName: string
      changedVal: string
      dictionaryName: string
      value: string
    OnRequestAttrManipulatorList:
    - action: string
      attributeName: string
      changedVal: string
      dictionaryName: string
      value: string
    RadiusServerList:
    - string
    continueAuthorzPolicy: true
    description: string
    localAccounting: true
    name: string
    prefixSeparator: string
    remoteAccounting: true
    stripPrefix: true
    stripSuffix: true
    suffixSeparator: string
    useAttrSetBeforeAcc: true
    useAttrSetOnRequest: true

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
