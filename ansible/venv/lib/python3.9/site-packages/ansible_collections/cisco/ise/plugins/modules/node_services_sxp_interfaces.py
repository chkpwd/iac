#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_services_sxp_interfaces
short_description: Resource module for Node Services SXP Interfaces
description:
- Manage operation update of the resource Node Services SXP Interfaces.
- This API configures the SXP interface.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  hostname:
    description: Hostname path parameter. Hostname of the node.
    type: str
  interface:
    description: Node Services SXP Interfaces's interface.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Node Services
  description: Complete reference of the Node Services API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    node_services.NodeServices.set_sxp_interface,

  - Paths used are
    put /api/v1/node/{hostname}/sxp-interface,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.node_services_sxp_interfaces:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    hostname: string
    interface: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "interface": "string"
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "success": {
        "message": "string"
      },
      "version": "string"
    }
"""
