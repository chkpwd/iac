#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_standalone_to_primary
short_description: Resource module for Node Standalone To Primary
description:
- Manage operation create of the resource Node Standalone To Primary.
- This API promotes the standalone node on which the API is invoked to the primary Policy Administration node PAN .
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  hostname:
    description: Hostname path parameter. Hostname of the node.
    type: str
    required: true
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Node Deployment
  description: Complete reference of the Node Deployment API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    node_deployment.NodeDeployment.make_primary,

  - Paths used are
    post /api/v1/deployment/primary,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.node_standalone_to_primary:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    hostname: string

"""

RETURN = r"""
ise_response:
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
