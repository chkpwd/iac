#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trustsec_vn_vlan_mapping_bulk_create
short_description: Resource module for Trustsec VN VLAN Mapping Bulk Create
description:
- Manage operation create of the resource Trustsec VN VLAN Mapping Bulk Create.
version_added: '2.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Trustsec VN VLAN Mapping Bulk Create's payload.
    elements: dict
    suboptions:
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
        description: Identifier for the associated Virtual Network which is required
          unless its name is provided.
        type: str
      vnName:
        description: Name of the associated Virtual Network to be used for identity
          if id is not provided.
        type: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for vnVlanMapping
  description: Complete reference of the vnVlanMapping API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!trustsec-openapi
notes:
  - SDK Method used are
    vn_vlan_mapping.VnVlanMapping.bulk_create_vn_vlan_mappings,

  - Paths used are
    post /api/v1/trustsec/vnvlanmapping/bulk/create,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.trustsec_vn_vlan_mapping_bulk_create:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    payload:
    - id: string
      isData: true
      isDefaultVlan: true
      lastUpdate: string
      maxValue: 0
      name: string
      vnId: string
      vnName: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string"
    }
"""
