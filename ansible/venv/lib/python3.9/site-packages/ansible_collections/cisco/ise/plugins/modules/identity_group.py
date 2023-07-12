#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: identity_group
short_description: Resource module for Identity Group
description:
- Manage operations create and update of the resource Identity Group.
- This API creates an identity group.
- This API allows the client to update an identity group.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Identity Group's description.
    type: str
  id:
    description: Identity Group's id.
    type: str
  name:
    description: Identity Group's name.
    type: str
  parent:
    description: Identity Group's parent.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for IdentityGroups
  description: Complete reference of the IdentityGroups API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!identitygroup
notes:
  - SDK Method used are
    identity_groups.IdentityGroups.create_identity_group,
    identity_groups.IdentityGroups.update_identity_group_by_id,

  - Paths used are
    post /ers/config/identitygroup,
    put /ers/config/identitygroup/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.identity_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    parent: string

- name: Create
  cisco.ise.identity_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
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
