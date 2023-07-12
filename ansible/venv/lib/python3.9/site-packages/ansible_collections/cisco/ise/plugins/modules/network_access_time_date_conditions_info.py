#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_time_date_conditions_info
short_description: Information module for Network Access Time Date Conditions
description:
- Get all Network Access Time Date Conditions.
- Get Network Access Time Date Conditions by id.
- Network Access - Returns a list of time and date conditions.
- Network Access - returns a network condition.
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
- name: Cisco ISE documentation for Network Access - Time/Date Conditions
  description: Complete reference of the Network Access - Time/Date Conditions API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_time_date_conditions.NetworkAccessTimeDateConditions.get_network_access_time_condition_by_id,
    network_access_time_date_conditions.NetworkAccessTimeDateConditions.get_network_access_time_conditions,

  - Paths used are
    get /network-access/time-condition,
    get /network-access/time-condition/{id},

"""

EXAMPLES = r"""
- name: Get all Network Access Time Date Conditions
  cisco.ise.network_access_time_date_conditions_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Network Access Time Date Conditions by id
  cisco.ise.network_access_time_date_conditions_info:
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
    {}
"""
