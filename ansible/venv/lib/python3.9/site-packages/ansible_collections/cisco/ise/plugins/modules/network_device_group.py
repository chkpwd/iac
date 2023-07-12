#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_group
short_description: Resource module for Network Device Group
description:
- Manage operations create, update and delete of the resource Network Device Group.
- This API creates a network device group.
- This API deletes a network device group.
- This API allows the client to update a network device group.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Network Device Group's description.
    type: str
  id:
    description: Network Device Group's id.
    type: str
  name:
    description: Network Device Group's name.
    type: str
  othername:
    description: Network Device Group's othername.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    network_device_group.NetworkDeviceGroup.create_network_device_group,
    network_device_group.NetworkDeviceGroup.delete_network_device_group_by_id,
    network_device_group.NetworkDeviceGroup.update_network_device_group_by_id,

  - Paths used are
    post /ers/config/networkdevicegroup,
    delete /ers/config/networkdevicegroup/{id},
    put /ers/config/networkdevicegroup/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.network_device_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    othername: string

- name: Delete by id
  cisco.ise.network_device_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.network_device_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    name: string
    othername: string

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
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      },
      "othername": "string"
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
