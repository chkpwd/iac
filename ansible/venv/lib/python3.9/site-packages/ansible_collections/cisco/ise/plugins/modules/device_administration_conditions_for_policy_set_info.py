#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_conditions_for_policy_set_info
short_description: Information module for Device Administration Conditions For Policy Set
description:
- Get all Device Administration Conditions For Policy Set.
- Device Admin - Returns list of library conditions for policy sets.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Conditions
  description: Complete reference of the Device Administration - Conditions API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_conditions.DeviceAdministrationConditions.get_device_admin_conditions_for_policy_sets,

  - Paths used are
    get /device-admin/condition/policyset,

"""

EXAMPLES = r"""
- name: Get all Device Administration Conditions For Policy Set
  cisco.ise.device_administration_conditions_for_policy_set_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

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
    ]
"""
