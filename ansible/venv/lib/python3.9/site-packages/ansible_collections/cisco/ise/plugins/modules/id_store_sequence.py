#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: id_store_sequence
short_description: Resource module for Id Store Sequence
description:
- Manage operations create, update and delete of the resource Id Store Sequence.
- This API creates an identity sequence.
- This API deletes an identity sequence.
- This API allows the client to update an identity sequence.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  breakOnStoreFail:
    description: BreakOnStoreFail flag.
    type: bool
  certificateAuthenticationProfile:
    description: Id Store Sequence's certificateAuthenticationProfile.
    type: str
  description:
    description: Id Store Sequence's description.
    type: str
  id:
    description: Id Store Sequence's id.
    type: str
  idSeqItem:
    description: Id Store Sequence's idSeqItem.
    elements: dict
    suboptions:
      idstore:
        description: Id Store Sequence's idstore.
        type: str
      order:
        description: Id Store Sequence's order.
        type: int
    type: list
  name:
    description: Id Store Sequence's name.
    type: str
  parent:
    description: Id Store Sequence's parent.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for IdentitySequence
  description: Complete reference of the IdentitySequence API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!idstoresequence
notes:
  - SDK Method used are
    identity_sequence.IdentitySequence.create_identity_sequence,
    identity_sequence.IdentitySequence.delete_identity_sequence_by_id,
    identity_sequence.IdentitySequence.update_identity_sequence_by_id,

  - Paths used are
    post /ers/config/idstoresequence,
    delete /ers/config/idstoresequence/{id},
    put /ers/config/idstoresequence/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.id_store_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    breakOnStoreFail: true
    certificateAuthenticationProfile: string
    description: string
    id: string
    idSeqItem:
    - idstore: string
      order: 0
    name: string
    parent: string

- name: Delete by id
  cisco.ise.id_store_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.id_store_sequence:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    breakOnStoreFail: true
    certificateAuthenticationProfile: string
    description: string
    idSeqItem:
    - idstore: string
      order: 0
    name: string
    parent: string

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
      "parent": "string",
      "idSeqItem": [
        {
          "idstore": "string",
          "order": 0
        }
      ],
      "certificateAuthenticationProfile": "string",
      "breakOnStoreFail": true,
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
