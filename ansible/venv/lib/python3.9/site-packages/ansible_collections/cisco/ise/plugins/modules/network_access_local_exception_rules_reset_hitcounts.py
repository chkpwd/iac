#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_local_exception_rules_reset_hitcounts
short_description: Resource module for Network Access Local Exception Rules Reset Hitcounts
description:
- Manage operation create of the resource Network Access Local Exception Rules Reset Hitcounts.
- Network Access - Reset HitCount for local exceptions.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  policyId:
    description: PolicyId path parameter. Policy id.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Network Access - Authorization Exception Rules
  description: Complete reference of the Network Access - Authorization Exception Rules API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_authorization_exception_rules.NetworkAccessAuthorizationExceptionRules.reset_hit_counts_network_access_local_exceptions,

  - Paths used are
    post /network-access/policy-set/{policyId}/exception/reset-hitcount,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.network_access_local_exception_rules_reset_hitcounts:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    policyId: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "message": "string"
    }
"""
