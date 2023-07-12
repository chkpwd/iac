#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_identity_stores_info
short_description: Information module for Network Access Identity Stores
description:
- Get all Network Access Identity Stores.
- Network Access - Return list of identity stores for authentication policy.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Network Access - Identity Stores
  description: Complete reference of the Network Access - Identity Stores API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_identity_stores.NetworkAccessIdentityStores.get_network_access_identity_stores,

  - Paths used are
    get /network-access/identity-stores,

"""

EXAMPLES = r"""
- name: Get all Network Access Identity Stores
  cisco.ise.network_access_identity_stores_info:
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
        "id": "string",
        "name": "string"
      }
    ]
"""
