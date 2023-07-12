#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_network_conditions_info
short_description: Information module for Device Administration Network Conditions
description:
- Get all Device Administration Network Conditions.
- Get Device Administration Network Conditions by id.
- Device Admin - Returns a list of network conditions.
- Device Admin - Returns a network condition.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter. Condition id.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Network Conditions
  description: Complete reference of the Device Administration - Network Conditions API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_network_conditions.DeviceAdministrationNetworkConditions.get_device_admin_network_condition_by_id,
    device_administration_network_conditions.DeviceAdministrationNetworkConditions.get_device_admin_network_conditions,

  - Paths used are
    get /device-admin/network-condition,
    get /device-admin/network-condition/{id},

"""

EXAMPLES = r"""
- name: Get all Device Administration Network Conditions
  cisco.ise.device_administration_network_conditions_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Device Administration Network Conditions by id
  cisco.ise.device_administration_network_conditions_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "conditionType": "string",
      "description": "string",
      "id": "string",
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "name": "string",
      "conditions": [
        {
          "cliDnisList": [
            "string"
          ],
          "conditionType": "string",
          "description": "string",
          "id": "string",
          "ipAddrList": [
            "string"
          ],
          "link": {
            "href": "string",
            "rel": "string",
            "type": "string"
          },
          "macAddrList": [
            "string"
          ],
          "name": "string",
          "deviceGroupList": [
            "string"
          ],
          "deviceList": [
            "string"
          ]
        }
      ]
    }
"""
