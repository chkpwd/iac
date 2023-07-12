#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_policy_set
short_description: Resource module for Network Access Policy Set
description:
- Manage operations create, update and delete of the resource Network Access Policy Set.
- Network Access - Create a new policy set.
- Network Access - Delete a policy set.
- Network Access - Update a policy set.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  condition:
    description: Network Access Policy Set's condition.
    suboptions:
      attributeName:
        description: Dictionary attribute name.
        type: str
      attributeValue:
        description: <ul><li>Attribute value for condition</li> <li>Value type is specified
          in dictionary object</li> <li>if multiple values allowed is specified in dictionary
          object</li></ul>.
        type: str
      children:
        description: In case type is andBlock or orBlock addtional conditions will be
          aggregated under this logical (OR/AND) condition.
        elements: dict
        suboptions:
          conditionType:
            description: <ul><li>Inidicates whether the record is the condition itself(data)
              or a logical(or,and) aggregation</li> <li>Data type enum(reference,single)
              indicates than "conditonId" OR "ConditionAttrs" fields should contain
              condition data but not both</li> <li>Logical aggreation(and,or) enum indicates
              that additional conditions are present under the children field</li></ul>.
            type: str
          isNegate:
            description: Indicates whereas this condition is in negate mode.
            type: bool
          link:
            description: Network Access Policy Set's link.
            suboptions:
              href:
                description: Network Access Policy Set's href.
                type: str
              rel:
                description: Network Access Policy Set's rel.
                type: str
              type:
                description: Network Access Policy Set's type.
                type: str
            type: dict
        type: list
      conditionType:
        description: <ul><li>Inidicates whether the record is the condition itself(data)
          or a logical(or,and) aggregation</li> <li>Data type enum(reference,single)
          indicates than "conditonId" OR "ConditionAttrs" fields should contain condition
          data but not both</li> <li>Logical aggreation(and,or) enum indicates that
          additional conditions are present under the children field</li></ul>.
        type: str
      datesRange:
        description: <p>Defines for which date/s TimeAndDate condition will be matched<br>
          Options are - Date range, for specific date, the same date should be used
          for start/end date <br> Default - no specific dates<br> In order to reset
          the dates to have no specific dates Date format - yyyy-mm-dd (MM = month,
          dd = day, yyyy = year)</p>.
        suboptions:
          endDate:
            description: Network Access Policy Set's endDate.
            type: str
          startDate:
            description: Network Access Policy Set's startDate.
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
            description: Network Access Policy Set's endDate.
            type: str
          startDate:
            description: Network Access Policy Set's startDate.
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
        description: <p>Defines for which hours a TimeAndDate condition will be matched<br>
          Time format - hh mm ( h = hour , mm = minutes ) <br> Default - All Day </p>.
        suboptions:
          endTime:
            description: Network Access Policy Set's endTime.
            type: str
          startTime:
            description: Network Access Policy Set's startTime.
            type: str
        type: dict
      hoursRangeException:
        description: <p>Defines for which hours a TimeAndDate condition will be matched<br>
          Time format - hh mm ( h = hour , mm = minutes ) <br> Default - All Day </p>.
        suboptions:
          endTime:
            description: Network Access Policy Set's endTime.
            type: str
          startTime:
            description: Network Access Policy Set's startTime.
            type: str
        type: dict
      id:
        description: Network Access Policy Set's id.
        type: str
      isNegate:
        description: Indicates whereas this condition is in negate mode.
        type: bool
      link:
        description: Network Access Policy Set's link.
        suboptions:
          href:
            description: Network Access Policy Set's href.
            type: str
          rel:
            description: Network Access Policy Set's rel.
            type: str
          type:
            description: Network Access Policy Set's type.
            type: str
        type: dict
      name:
        description: Condition name.
        type: str
      operator:
        description: Equality operator.
        type: str
      weekDays:
        description: <p>Defines for which days this condition will be matched<br> Days
          format - Arrays of WeekDay enums <br> Default - List of All week days</p>.
        elements: str
        type: list
      weekDaysException:
        description: <p>Defines for which days this condition will NOT be matched<br>
          Days format - Arrays of WeekDay enums <br> Default - Not enabled</p>.
        elements: str
        type: list
    type: dict
  default:
    description: Flag which indicates if this policy set is the default one.
    type: bool
  description:
    description: The description for the policy set.
    type: str
  hitCounts:
    description: The amount of times the policy was matched.
    type: int
  id:
    description: Identifier for the policy set.
    type: str
  isProxy:
    description: Flag which indicates if the policy set service is of type 'Proxy Sequence'
      or 'Allowed Protocols'.
    type: bool
  link:
    description: Network Access Policy Set's link.
    suboptions:
      href:
        description: Network Access Policy Set's href.
        type: str
      rel:
        description: Network Access Policy Set's rel.
        type: str
      type:
        description: Network Access Policy Set's type.
        type: str
    type: dict
  name:
    description: Given name for the policy set, Valid characters are alphanumerics,
      underscore, hyphen, space, period, parentheses.
    type: str
  rank:
    description: The rank(priority) in relation to other policy set. Lower rank is higher
      priority.
    type: int
  serviceName:
    description: Policy set service identifier - Allowed Protocols,Server Sequence..
    type: str
  state_:
    description: The state that the policy set is in. A disabled policy set cannot be
      matched.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Network Access - Policy Set
  description: Complete reference of the Network Access - Policy Set API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_policy_set.NetworkAccessPolicySet.create_network_access_policy_set,
    network_access_policy_set.NetworkAccessPolicySet.delete_network_access_policy_set_by_id,
    network_access_policy_set.NetworkAccessPolicySet.update_network_access_policy_set_by_id,

  - Paths used are
    post /network-access/policy-set,
    delete /network-access/policy-set/{id},
    put /network-access/policy-set/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.network_access_policy_set:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
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
    description: string
    hitCounts: 0
    id: string
    isProxy: true
    link:
      href: string
      rel: string
      type: string
    name: string
    rank: 0
    serviceName: string
    state_: string

- name: Update by id
  cisco.ise.network_access_policy_set:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
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
    description: string
    hitCounts: 0
    id: string
    isProxy: true
    link:
      href: string
      rel: string
      type: string
    name: string
    rank: 0
    serviceName: string
    state_: string

- name: Delete by id
  cisco.ise.network_access_policy_set:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
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
      "description": "string",
      "hitCounts": 0,
      "id": "string",
      "isProxy": true,
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "name": "string",
      "rank": 0,
      "serviceName": "string",
      "state": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "response": {
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
        "description": "string",
        "hitCounts": 0,
        "id": "string",
        "isProxy": true,
        "link": {
          "href": "string",
          "rel": "string",
          "type": "string"
        },
        "name": "string",
        "rank": 0,
        "serviceName": "string",
        "state": "string"
      },
      "version": "string"
    }
"""
