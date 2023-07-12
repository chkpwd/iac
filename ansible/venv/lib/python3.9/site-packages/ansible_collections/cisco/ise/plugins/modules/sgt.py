#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sgt
short_description: Resource module for SGt
description:
- Manage operations create, update and delete of the resource SGt.
- This API creates a security group.
- This API deletes a security group.
- This API allows the client to update a security group.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  defaultSGACLs:
    description: SGt's defaultSGACLs.
    elements: dict
    type: list
  description:
    description: SGt's description.
    type: str
  generationId:
    description: SGt's generationId.
    type: str
  id:
    description: SGt's id.
    type: str
  isReadOnly:
    description: IsReadOnly flag.
    type: bool
  name:
    description: SGt's name.
    type: str
    required: true
  propogateToApic:
    description: PropogateToApic flag.
    type: bool
  value:
    description: Value range 2 ot 65519 or -1 to auto-generate.
    type: int
    required: true
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for SecurityGroups
  description: Complete reference of the SecurityGroups API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sgt
notes:
  - SDK Method used are
    security_groups.SecurityGroups.create_security_group,
    security_groups.SecurityGroups.delete_security_group_by_id,
    security_groups.SecurityGroups.update_security_group_by_id,

  - Paths used are
    post /ers/config/sgt,
    delete /ers/config/sgt/{id},
    put /ers/config/sgt/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.sgt:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    defaultSGACLs:
    - {}
    description: string
    generationId: string
    id: string
    isReadOnly: true
    name: string
    propogateToApic: true
    value: 0

- name: Delete by id
  cisco.ise.sgt:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sgt:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    defaultSGACLs:
    - {}
    description: string
    generationId: string
    isReadOnly: true
    name: string
    propogateToApic: true
    value: 0

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
      "value": 0,
      "generationId": "string",
      "isReadOnly": true,
      "propogateToApic": true,
      "defaultSGACLs": [
        {}
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
