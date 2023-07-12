#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sg_to_vn_to_vlan
short_description: Resource module for SG To VN To VLAN
description:
- Manage operations create, update and delete of the resource SG To VN To VLAN.
- This API creates a security group to virtual network.
- This API deletes a security group ACL to virtual network.
- This API allows the client to update a security group to virtual network.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: SG To VN To VLAN's description.
    type: str
  id:
    description: SG To VN To VLAN's id.
    type: str
  name:
    description: SG To VN To VLAN's name.
    type: str
  sgtId:
    description: SG To VN To VLAN's sgtId.
    type: str
  virtualnetworklist:
    description: SG To VN To VLAN's virtualnetworklist.
    elements: dict
    suboptions:
      defaultVirtualNetwork:
        description: DefaultVirtualNetwork flag.
        type: bool
      description:
        description: SG To VN To VLAN's description.
        type: str
      id:
        description: SG To VN To VLAN's id.
        type: str
      name:
        description: SG To VN To VLAN's name.
        type: str
      vlans:
        description: SG To VN To VLAN's vlans.
        elements: dict
        suboptions:
          data:
            description: Data flag.
            type: bool
          defaultVLAN:
            description: DefaultVLAN flag.
            type: bool
          description:
            description: SG To VN To VLAN's description.
            type: str
          id:
            description: SG To VN To VLAN's id.
            type: str
          maxValue:
            description: SG To VN To VLAN's maxValue.
            type: int
          name:
            description: SG To VN To VLAN's name.
            type: str
        type: list
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for SecurityGroupToVirtualNetwork
  description: Complete reference of the SecurityGroupToVirtualNetwork API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sgtvnvlan
notes:
  - SDK Method used are
    security_group_to_virtual_network.SecurityGroupToVirtualNetwork.create_security_groups_to_vn_to_vlan,
    security_group_to_virtual_network.SecurityGroupToVirtualNetwork.delete_security_groups_to_vn_to_vlan_by_id,
    security_group_to_virtual_network.SecurityGroupToVirtualNetwork.update_security_groups_to_vn_to_vlan_by_id,

  - Paths used are
    post /ers/config/sgtvnvlan,
    delete /ers/config/sgtvnvlan/{id},
    put /ers/config/sgtvnvlan/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.sg_to_vn_to_vlan:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    sgtId: string
    virtualnetworklist:
    - defaultVirtualNetwork: true
      description: string
      id: string
      name: string
      vlans:
      - data: true
        defaultVlan: true
        description: string
        id: string
        maxValue: 0
        name: string

- name: Delete by id
  cisco.ise.sg_to_vn_to_vlan:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sg_to_vn_to_vlan:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    sgtId: string
    virtualnetworklist:
    - defaultVirtualNetwork: true
      description: string
      id: string
      name: string
      vlans:
      - data: true
        defaultVlan: true
        description: string
        id: string
        maxValue: 0
        name: string

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
      "sgtId": "string",
      "virtualnetworklist": [
        {
          "id": "string",
          "name": "string",
          "description": "string",
          "defaultVirtualNetwork": true,
          "vlans": [
            {
              "id": "string",
              "name": "string",
              "description": "string",
              "defaultVlan": true,
              "maxValue": 0,
              "data": true
            }
          ]
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
