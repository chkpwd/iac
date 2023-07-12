#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sxp_local_bindings_bulk_request
short_description: Resource module for SXP Local Bindings Bulk Request
description:
- Manage operation update of the resource SXP Local Bindings Bulk Request.
- This API allows the client to submit the bulk request.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  operationType:
    description: SXP Local Bindings Bulk Request's operationType.
    type: str
  resourceMediaType:
    description: SXP Local Bindings Bulk Request's resourceMediaType.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    sxp_local_bindings.SxpLocalBindings.bulk_request_for_sxp_local_bindings,

  - Paths used are
    put /ers/config/sxplocalbindings/bulk/submit,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.sxp_local_bindings_bulk_request:
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
