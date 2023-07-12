#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_global_exception_rules_info
short_description: Information module for Device Administration Global Exception Rules
description:
- Get all Device Administration Global Exception Rules.
- Get Device Administration Global Exception Rules by id.
- Device Admin - Get global exception rule attribute.
- Device Admin - Get global execption rules.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter. Rule id.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Authorization Global Exception Rules
  description: Complete reference of the Device Administration - Authorization Global Exception Rules API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_authorization_global_exception_rules.DeviceAdministrationAuthorizationGlobalExceptionRules.get_device_admin_policy_set_global_exception_by_rule_id,
    device_administration_authorization_global_exception_rules.DeviceAdministrationAuthorizationGlobalExceptionRules.get_device_admin_policy_set_global_exception_rules,

  - Paths used are
    get /device-admin/policy-set/global-exception,
    get /device-admin/policy-set/global-exception/{id},

"""

EXAMPLES = r"""
- name: Get all Device Administration Global Exception Rules
  cisco.ise.device_administration_global_exception_rules_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Device Administration Global Exception Rules by id
  cisco.ise.device_administration_global_exception_rules_info:
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
      "commands": [
        "string"
      ],
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "profile": "string",
      "rule": {
        "condition": {
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
        },
        "default": true,
        "hitCounts": 0,
        "id": "string",
        "name": "string",
        "rank": 0,
        "state": "string"
      }
    }
"""
