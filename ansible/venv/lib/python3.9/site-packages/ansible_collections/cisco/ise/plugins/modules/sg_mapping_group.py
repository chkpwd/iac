#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sg_mapping_group
short_description: Resource module for SG Mapping Group
description:
- Manage operations create, update and delete of the resource SG Mapping Group.
- This API creates an IP to SGT mapping group.
- This API deletes an IP to SGT mapping group.
- This API allows the client to update an IP to SGT mapping group by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  deployTo:
    description: Mandatory unless mappingGroup is set or unless deployType=ALL.
    type: str
  deployType:
    description: Allowed values - ALL, - ND, - NDG.
    type: str
  id:
    description: Id path parameter.
    type: str
  name:
    description: SG Mapping Group's name.
    type: str
  sgt:
    description: Mandatory unless mappingGroup is set.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for IPToSGTMappingGroup
  description: Complete reference of the IPToSGTMappingGroup API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sgmappinggroup
notes:
  - SDK Method used are
    ip_to_sgt_mapping_group.IpToSgtMappingGroup.create_ip_to_sgt_mapping_group,
    ip_to_sgt_mapping_group.IpToSgtMappingGroup.delete_ip_to_sgt_mapping_group_by_id,
    ip_to_sgt_mapping_group.IpToSgtMappingGroup.update_ip_to_sgt_mapping_group_by_id,

  - Paths used are
    post /ers/config/sgmappinggroup,
    delete /ers/config/sgmappinggroup/{id},
    put /ers/config/sgmappinggroup/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.sg_mapping_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    deployTo: string
    deployType: string
    id: string
    name: string
    sgt: string

- name: Delete by id
  cisco.ise.sg_mapping_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sg_mapping_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    deployTo: string
    deployType: string
    name: string
    sgt: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "name": "string",
      "sgt": "string",
      "deployTo": "string",
      "deployType": "string",
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
