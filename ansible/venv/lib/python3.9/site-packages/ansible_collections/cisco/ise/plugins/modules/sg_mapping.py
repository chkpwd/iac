#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sg_mapping
short_description: Resource module for SG Mapping
description:
- Manage operations create, update and delete of the resource SG Mapping.
- This API creates an IP to SGT mapping.
- This API deletes an IP to SGT mapping.
- This API allows the client to update an IP to SGT mapping by ID.
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
  hostIp:
    description: Mandatory if hostName is empty -- valid IP.
    type: str
  hostName:
    description: Mandatory if hostIp is empty.
    type: str
  id:
    description: SG Mapping's id.
    type: str
  mappingGroup:
    description: Mapping Group Id. Mandatory unless sgt and deployTo and deployType
      are set.
    type: str
  name:
    description: SG Mapping's name.
    type: str
  sgt:
    description: Mandatory unless mappingGroup is set.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for IPToSGTMapping
  description: Complete reference of the IPToSGTMapping API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sgmapping
notes:
  - SDK Method used are
    ip_to_sgt_mapping.IpToSgtMapping.create_ip_to_sgt_mapping,
    ip_to_sgt_mapping.IpToSgtMapping.delete_ip_to_sgt_mapping_by_id,
    ip_to_sgt_mapping.IpToSgtMapping.update_ip_to_sgt_mapping_by_id,

  - Paths used are
    post /ers/config/sgmapping,
    delete /ers/config/sgmapping/{id},
    put /ers/config/sgmapping/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.sg_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    deployTo: string
    deployType: string
    hostIp: string
    hostName: string
    id: string
    mappingGroup: string
    name: string
    sgt: string

- name: Delete by id
  cisco.ise.sg_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sg_mapping:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    deployTo: string
    deployType: string
    hostIp: string
    hostName: string
    mappingGroup: string
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
      "id": "string",
      "name": "string",
      "sgt": "string",
      "deployTo": "string",
      "deployType": "string",
      "hostName": "string",
      "hostIp": "string",
      "mappingGroup": "string",
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
