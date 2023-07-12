#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_network_condition_info
short_description: Information module for Network Access Network Condition
description:
- Get all Network Access Network Condition.
- Get Network Access Network Condition by id.
- Network Access - Returns a list of network conditions.
- Network Access - Returns a network condition.
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
- name: Cisco ISE documentation for Network Access - Network Conditions
  description: Complete reference of the Network Access - Network Conditions API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_network_conditions.NetworkAccessNetworkConditions.get_network_access_network_condition_by_id,
    network_access_network_conditions.NetworkAccessNetworkConditions.get_network_access_network_conditions,

  - Paths used are
    get /network-access/network-condition,
    get /network-access/network-condition/{id},

"""

EXAMPLES = r"""
- name: Get all Network Access Network Condition
  cisco.ise.network_access_network_condition_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Network Access Network Condition by id
  cisco.ise.network_access_network_condition_info:
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
      "deviceList": [
        "string"
      ],
      "cliDnisList": [
        "string"
      ],
      "ipAddrList": [
        "string"
      ],
      "macAddrList": [
        "string"
      ],
      "deviceGroupList": [
        "string"
      ]
    }
"""
