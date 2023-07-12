#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: anc_endpoint_apply
short_description: Resource module for ANC Endpoint Apply
description:
- Manage operation update of the resource ANC Endpoint Apply.
- This API allows the client to apply the required configuration.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  additionalData:
    description: ANC Endpoint Apply's additionalData.
    elements: dict
    suboptions:
      name:
        description: ANC Endpoint Apply's name.
        type: str
      value:
        description: ANC Endpoint Apply's value.
        type: str
    type: list
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    anc_endpoint.AncEndpoint.apply_anc_endpoint,

  - Paths used are
    put /ers/config/ancendpoint/apply,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.anc_endpoint_apply:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    additionalData:
    - name: macAddress
      value: MAC address
    - name: ipAddress
      value: IP address
    - name: policyName
      value: Policy Name

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
