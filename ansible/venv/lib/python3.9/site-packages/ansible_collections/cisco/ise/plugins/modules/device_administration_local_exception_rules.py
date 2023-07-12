#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_administration_local_exception_rules
short_description: Resource module for Device Administration Local Exception Rules
description:
- Manage operations create, update and delete of the resource Device Administration Local Exception Rules.
- Device Admin - Create local authorization exception rule.
- Device Admin - Delete local exception rule.
- Device Admin - Update local exception rule.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  commands:
    description: Command sets enforce the specified list of commands that can be executed
      by a device administrator.
    elements: str
    type: list
  id:
    description: Id path parameter. Rule id.
    type: str
  link:
    description: Device Administration Local Exception Rules's link.
    suboptions:
      href:
        description: Device Administration Local Exception Rules's href.
        type: str
      rel:
        description: Device Administration Local Exception Rules's rel.
        type: str
      type:
        description: Device Administration Local Exception Rules's type.
        type: str
    type: dict
  policyId:
    description: PolicyId path parameter. Policy id.
    type: str
  profile:
    description: Device admin profiles control the initial login session of the device
      administrator.
    type: str
  rule:
    description: Common attributes in rule authentication/authorization.
    suboptions:
      condition:
        description: Device Administration Local Exception Rules's condition.
        suboptions:
          attributeName:
            description: Dictionary attribute name.
            type: str
          attributeValue:
            description: <ul><li>Attribute value for condition</li> <li>Value type is
              specified in dictionary object</li> <li>if multiple values allowed is
              specified in dictionary object</li></ul>.
            type: str
          children:
            description: In case type is andBlock or orBlock addtional conditions will
              be aggregated under this logical (OR/AND) condition.
            elements: dict
            suboptions:
              conditionType:
                description: <ul><li>Inidicates whether the record is the condition
                  itself(data) or a logical(or,and) aggregation</li> <li>Data type enum(reference,single)
                  indicates than "conditonId" OR "ConditionAttrs" fields should contain
                  condition data but not both</li> <li>Logical aggreation(and,or) enum
                  indicates that additional conditions are present under the children
                  field</li></ul>.
                type: str
              isNegate:
                description: Indicates whereas this condition is in negate mode.
                type: bool
              link:
                description: Device Administration Local Exception Rules's link.
                suboptions:
                  href:
                    description: Device Administration Local Exception Rules's href.
                    type: str
                  rel:
                    description: Device Administration Local Exception Rules's rel.
                    type: str
                  type:
                    description: Device Administration Local Exception Rules's type.
                    type: str
                type: dict
            type: list
          conditionType:
            description: <ul><li>Inidicates whether the record is the condition itself(data)
              or a logical(or,and) aggregation</li> <li>Data type enum(reference,single)
              indicates than "conditonId" OR "ConditionAttrs" fields should contain
              condition data but not both</li> <li>Logical aggreation(and,or) enum indicates
              that additional conditions are present under the children field</li></ul>.
            type: str
          datesRange:
            description: <p>Defines for which date/s TimeAndDate condition will be matched<br>
              Options are - Date range, for specific date, the same date should be used
              for start/end date <br> Default - no specific dates<br> In order to reset
              the dates to have no specific dates Date format - yyyy-mm-dd (MM = month,
              dd = day, yyyy = year)</p>.
            suboptions:
              endDate:
                description: Device Administration Local Exception Rules's endDate.
                type: str
              startDate:
                description: Device Administration Local Exception Rules's startDate.
                type: str
            type: dict
          datesRangeException:
            description: <p>Defines for which date/s TimeAndDate condition will be matched<br>
              Options are - Date range, for specific date, the same date should be used
              for start/end date <br> Default - no specific dates<br> In order to reset
              the dates to have no specific dates Date format - yyyy-mm-dd (MM = month,
              dd = day, yyyy = year)</p>.
            suboptions:
              endDate:
                description: Device Administration Local Exception Rules's endDate.
                type: str
              startDate:
                description: Device Administration Local Exception Rules's startDate.
                type: str
            type: dict
          description:
            description: Condition description.
            type: str
          dictionaryName:
            description: Dictionary name.
            type: str
          dictionaryValue:
            description: Dictionary value.
            type: str
          hoursRange:
            description: <p>Defines for which hours a TimeAndDate condition will be
              matched<br> Time format - hh mm ( h = hour , mm = minutes ) <br> Default
              - All Day </p>.
            suboptions:
              endTime:
                description: Device Administration Local Exception Rules's endTime.
                type: str
              startTime:
                description: Device Administration Local Exception Rules's startTime.
                type: str
            type: dict
          hoursRangeException:
            description: <p>Defines for which hours a TimeAndDate condition will be
              matched<br> Time format - hh mm ( h = hour , mm = minutes ) <br> Default
              - All Day </p>.
            suboptions:
              endTime:
                description: Device Administration Local Exception Rules's endTime.
                type: str
              startTime:
                description: Device Administration Local Exception Rules's startTime.
                type: str
            type: dict
          id:
            description: Device Administration Local Exception Rules's id.
            type: str
          isNegate:
            description: Indicates whereas this condition is in negate mode.
            type: bool
          link:
            description: Device Administration Local Exception Rules's link.
            suboptions:
              href:
                description: Device Administration Local Exception Rules's href.
                type: str
              rel:
                description: Device Administration Local Exception Rules's rel.
                type: str
              type:
                description: Device Administration Local Exception Rules's type.
                type: str
            type: dict
          name:
            description: Condition name.
            type: str
          operator:
            description: Equality operator.
            type: str
          weekDays:
            description: <p>Defines for which days this condition will be matched<br>
              Days format - Arrays of WeekDay enums <br> Default - List of All week
              days</p>.
            elements: str
            type: list
          weekDaysException:
            description: <p>Defines for which days this condition will NOT be matched<br>
              Days format - Arrays of WeekDay enums <br> Default - Not enabled</p>.
            elements: str
            type: list
        type: dict
      default:
        description: Indicates if this rule is the default one.
        type: bool
      hitCounts:
        description: The amount of times the rule was matched.
        type: int
      id:
        description: The identifier of the rule.
        type: str
      name:
        description: Rule name, Valid characters are alphanumerics, underscore, hyphen,
          space, period, parentheses.
        type: str
      rank:
        description: The rank(priority) in relation to other rules. Lower rank is higher
          priority.
        type: int
      state:
        description: The state that the rule is in. A disabled rule cannot be matched.
        type: str
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Device Administration - Authorization Exception Rules
  description: Complete reference of the Device Administration - Authorization Exception Rules API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    device_administration_authorization_exception_rules.DeviceAdministrationAuthorizationExceptionRules.create_device_admin_local_exception_rule,
    device_administration_authorization_exception_rules.DeviceAdministrationAuthorizationExceptionRules.delete_device_admin_local_exception_rule_by_id,
    device_administration_authorization_exception_rules.DeviceAdministrationAuthorizationExceptionRules.update_device_admin_local_exception_rule_by_id,

  - Paths used are
    post /device-admin/policy-set/{policyId}/exception,
    delete /device-admin/policy-set/{policyId}/exception/{id},
    put /device-admin/policy-set/{policyId}/exception/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.device_administration_local_exception_rules:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    commands:
    - string
    link:
      href: string
      rel: string
      type: string
    policyId: string
    profile: string
    rule:
      condition:
        attributeName: string
        attributeValue: string
        children:
        - conditionType: string
          isNegate: true
          link:
            href: string
            rel: string
            type: string
        conditionType: string
        datesRange:
          endDate: string
          startDate: string
        datesRangeException:
          endDate: string
          startDate: string
        description: string
        dictionaryName: string
        dictionaryValue: string
        hoursRange:
          endTime: string
          startTime: string
        hoursRangeException:
          endTime: string
          startTime: string
        id: string
        isNegate: true
        link:
          href: string
          rel: string
          type: string
        name: string
        operator: string
        weekDays:
        - string
        weekDaysException:
        - string
      default: true
      hitCounts: 0
      id: string
      name: string
      rank: 0
      state: string

- name: Update by id
  cisco.ise.device_administration_local_exception_rules:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    commands:
    - string
    id: string
    link:
      href: string
      rel: string
      type: string
    policyId: string
    profile: string
    rule:
      condition:
        attributeName: string
        attributeValue: string
        children:
        - conditionType: string
          isNegate: true
          link:
            href: string
            rel: string
            type: string
        conditionType: string
        datesRange:
          endDate: string
          startDate: string
        datesRangeException:
          endDate: string
          startDate: string
        description: string
        dictionaryName: string
        dictionaryValue: string
        hoursRange:
          endTime: string
          startTime: string
        hoursRangeException:
          endTime: string
          startTime: string
        id: string
        isNegate: true
        link:
          href: string
          rel: string
          type: string
        name: string
        operator: string
        weekDays:
        - string
        weekDaysException:
        - string
      default: true
      hitCounts: 0
      id: string
      name: string
      rank: 0
      state: string

- name: Delete by id
  cisco.ise.device_administration_local_exception_rules:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string
    policyId: string

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

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "response": {
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
      },
      "version": "string"
    }
"""
