#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: id_store_sequence_info
short_description: Information module for Id Store Sequence
description:
- Get all Id Store Sequence.
- Get Id Store Sequence by id.
- Get Id Store Sequence by name.
- This API allows the client to get all the identity sequences.
- This API allows the client to get an identity sequence by ID.
- This API allows the client to get an identity sequence by name.
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
seealso:
- name: Cisco ISE documentation for IdentitySequence
  description: Complete reference of the IdentitySequence API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!idstoresequence
notes:
  - SDK Method used are
    identity_sequence.IdentitySequence.get_identity_sequence_by_id,
    identity_sequence.IdentitySequence.get_identity_sequence_by_name,
    identity_sequence.IdentitySequence.get_identity_sequence_generator,

  - Paths used are
    get /ers/config/idstoresequence,
    get /ers/config/idstoresequence/name/{name},
    get /ers/config/idstoresequence/{id},

"""

EXAMPLES = r"""
- name: Get all Id Store Sequence
  cisco.ise.id_store_sequence_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Id Store Sequence by id
  cisco.ise.id_store_sequence_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Id Store Sequence by name
  cisco.ise.id_store_sequence_info:
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
    ]
"""
