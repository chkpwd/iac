#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_promotion
short_description: Resource module for Node Promotion
description:
- Manage operation update of the resource Node Promotion.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  promotionType:
    description: Node Promotion's promotionType.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    node_deployment.NodeDeployment.promote_node,

  - Paths used are
    put /api/v1/deployment/node-promotion/,
"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.node_promotion:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    promotionType: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "code": 0,
      "message": "string",
      "rootCause": "string"
    }
"""
