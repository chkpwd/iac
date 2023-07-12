#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trustsec_vn_vlan_mapping
short_description: Resource module for Trustsec VN VLAN Mapping
description:
- Manage operations create, update and delete of the resource Trustsec VN VLAN Mapping.
- Create VN-Vlan Mapping.
- Update VN-Vlan Mapping.
version_added: '2.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Identifier of the VN-VLAN Mapping.
    type: str
  isData:
    description: Flag which indicates whether the VLAN is data or voice type.
    type: bool
  isDefaultVLAN:
    description: Flag which indicates if the VLAN is default.
    type: bool
  lastUpdate:
    description: Timestamp for the last update of the VN-VLAN Mapping.
    type: str
  maxValue:
    description: Max value.
    type: int
  name:
    description: Name of the VLAN.
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
- name: Cisco ISE documentation for vnVlanMapping
  description: Complete reference of the vnVlanMapping API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!trustsec-openapi
notes:
  - SDK Method used are
    vn_vlan_mapping.VnVlanMapping.create_vn_vlan_mapping,
    vn_vlan_mapping.VnVlanMapping.delete_vn_vlan_mapping_by_id,
    vn_vlan_mapping.VnVlanMapping.update_vn_vlan_mapping_by_id,

  - Paths used are
    post /api/v1/trustsec/vnvlanmapping,
    delete /api/v1/trustsec/vnvlanmapping/{id},
    put /api/v1/trustsec/vnvlanmapping/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.trustsec_vn_vlan_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    id: string
    isData: true
    isDefaultVlan: true
    lastUpdate: string
    maxValue: 0
    name: string
    vnId: string
    vnName: string

- name: Update by id
  cisco.ise.trustsec_vn_vlan_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    id: string
    isData: true
    isDefaultVlan: true
    lastUpdate: string
    maxValue: 0
    name: string
    vnId: string
    vnName: string

- name: Delete by id
  cisco.ise.trustsec_vn_vlan_mapping:
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
        "isData": true,
        "isDefaultVlan": true,
        "lastUpdate": "string",
        "maxValue": 0,
        "name": "string",
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
