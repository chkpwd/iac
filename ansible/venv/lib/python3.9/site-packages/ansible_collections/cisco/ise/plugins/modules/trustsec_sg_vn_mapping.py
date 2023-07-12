#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trustsec_sg_vn_mapping
short_description: Resource module for Trustsec SG VN Mapping
description:
- Manage operations create, update and delete of the resource Trustsec SG VN Mapping.
- Create Security Group and Virtual Network mapping.
- Delete Security Group and Virtual Network mapping.
- Update Security Group and Virtual Network mapping.
version_added: '2.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Identifier of the SG-VN mapping.
    type: str
  lastUpdate:
    description: Timestamp for the last update of the SG-VN mapping.
    type: str
  sgName:
    description: Name of the associated Security Group to be used for identity if id
      is not provided.
    type: str
  sgtId:
    description: Identifier of the associated Security Group which is required unless
      its name is provided.
    type: str
  vnId:
    description: Identifier for the associated Virtual Network which is required unless
      its name is provided.
    type: str
  vnName:
    description: Name of the associated Virtual Network to be used for identity if id
      is not provided.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for sgVnMapping
  description: Complete reference of the sgVnMapping API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!trustsec-openapi
notes:
  - SDK Method used are
    sg_vn_mapping.SgVnMapping.create_sg_vn_mapping,
    sg_vn_mapping.SgVnMapping.delete_sg_vn_mapping_by_id,
    sg_vn_mapping.SgVnMapping.update_sg_vn_mapping_by_id,

  - Paths used are
    post /api/v1/trustsec/sgvnmapping,
    delete /api/v1/trustsec/sgvnmapping/{id},
    put /api/v1/trustsec/sgvnmapping/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.trustsec_sg_vn_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    id: string
    lastUpdate: string
    sgName: string
    sgtId: string
    vnId: string
    vnName: string

- name: Update by id
  cisco.ise.trustsec_sg_vn_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    id: string
    lastUpdate: string
    sgName: string
    sgtId: string
    vnId: string
    vnName: string

- name: Delete by id
  cisco.ise.trustsec_sg_vn_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "lastUpdate": "string",
        "sgName": "string",
        "sgtId": "string",
        "vnId": "string",
        "vnName": "string"
      }
    ]

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "code": 0,
      "message": "string"
    }
"""
