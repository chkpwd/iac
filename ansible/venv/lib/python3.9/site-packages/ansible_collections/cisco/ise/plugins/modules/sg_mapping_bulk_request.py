#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sg_mapping_bulk_request
short_description: Resource module for SG Mapping Bulk Request
description:
- Manage operation update of the resource SG Mapping Bulk Request.
- This API allows the client to submit the bulk request.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  operationType:
    description: SG Mapping Bulk Request's operationType.
    type: str
  resourceMediaType:
    description: SG Mapping Bulk Request's resourceMediaType.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for IPToSGTMapping
  description: Complete reference of the IPToSGTMapping API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sgmapping
notes:
  - SDK Method used are
    ip_to_sgt_mapping.IpToSgtMapping.bulk_request_for_ip_to_sgt_mapping,

  - Paths used are
    put /ers/config/sgmapping/bulk/submit,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.sg_mapping_bulk_request:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    operationType: string
    resourceMediaType: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
