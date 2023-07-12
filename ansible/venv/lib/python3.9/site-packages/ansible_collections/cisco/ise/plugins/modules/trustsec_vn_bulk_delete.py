#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: trustsec_vn_bulk_delete
short_description: Resource module for Trustsec VN Bulk Delete
description:
- Manage operation create of the resource Trustsec VN Bulk Delete.
version_added: '2.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Trustsec VN Bulk Delete's payload.
    elements: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for virtualNetwork
  description: Complete reference of the virtualNetwork API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!trustsec-openapi
notes:
  - SDK Method used are
    virtual_network.VirtualNetwork.bulk_delete_virtual_networks,

  - Paths used are
    post /api/v1/trustsec/virtualnetwork/bulk/delete,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.trustsec_vn_bulk_delete:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    payload:
    - string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string"
    }
"""
