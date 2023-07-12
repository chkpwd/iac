#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_primary_to_standalone
short_description: Resource module for Node Primary To Standalone
description:
- Manage operation create of the resource Node Primary To Standalone.
- This API changes the primary PAN in a single node cluster on which the API is invoked, to a standalone node.
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
    node_deployment.NodeDeployment.make_standalone,

  - Paths used are
    post /api/v1/deployment/standalone,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.node_primary_to_standalone:
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
