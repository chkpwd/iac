#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_conditions_info
short_description: Information module for Device Administration Conditions
description:
- Get all Device Administration Conditions.
- Get Device Administration Conditions by id.
- Get Device Administration Conditions by name.
- Device Admin - Returns a library condition.
- Device Admin - Returns a library condition.
- Device Admin - Returns list of library conditions.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  name:
    description:
    - Name path parameter. Condition name.
    type: str
  id:
    description:
    - Id path parameter. Condition id.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Conditions
  description: Complete reference of the Device Administration - Conditions API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_conditions.DeviceAdministrationConditions.get_device_admin_condition_by_id,
    device_administration_conditions.DeviceAdministrationConditions.get_device_admin_condition_by_name,
    device_administration_conditions.DeviceAdministrationConditions.get_device_admin_conditions,

  - Paths used are
    get /device-admin/condition,
    get /device-admin/condition/condition-by-name/{name},
    get /device-admin/condition/{id},

"""

EXAMPLES = r"""
- name: Get all Device Administration Conditions
  cisco.ise.device_administration_conditions_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Device Administration Conditions by id
  cisco.ise.device_administration_conditions_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Device Administration Conditions by name
  cisco.ise.device_administration_conditions_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
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
      "isNegate": true,
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "description": "string",
      "id": "string",
      "name": "string",
      "attributeName": "string",
      "attributeValue": "string",
      "dictionaryName": "string",
      "dictionaryValue": "string",
      "operator": "string",
      "children": [
        {
          "conditionType": "string",
          "isNegate": true,
          "link": {
            "href": "string",
            "rel": "string",
            "type": "string"
          }
        }
      ],
      "datesRange": {
        "endDate": "string",
        "startDate": "string"
      },
      "datesRangeException": {
        "endDate": "string",
        "startDate": "string"
      },
      "hoursRange": {
        "endTime": "string",
        "startTime": "string"
      },
      "hoursRangeException": {
        "endTime": "string",
        "startTime": "string"
      },
      "weekDays": [
        "string"
      ],
      "weekDaysException": [
        "string"
      ]
    }
"""
