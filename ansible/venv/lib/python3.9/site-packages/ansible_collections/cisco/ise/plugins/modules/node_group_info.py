#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_group_info
short_description: Information module for Node Group
description:
- Get all Node Group.
- Get Node Group by name.
- This API retrieves the details of a node group in the cluster using a node group name.
- This API retrieves the details of all the node groups in the cluster.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  nodeGroupName:
    description:
    - NodeGroupName path parameter. Name of the existing node group.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Node Group
  description: Complete reference of the Node Group API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    node_group.NodeGroup.get_node_group,
    node_group.NodeGroup.get_node_groups,

  - Paths used are
    get /api/v1/deployment/node-group,
    get /api/v1/deployment/node-group/{nodeGroupName},

"""

EXAMPLES = r"""
- name: Get all Node Group
  cisco.ise.node_group_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

- name: Get Node Group by name
  cisco.ise.node_group_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    nodeGroupName: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "description": "string",
      "marCache": {
        "query-attempts": 0,
        "query-timeout": 0,
        "replication-attempts": 0,
        "replication-timeout": 0
      },
      "name": "string"
    }
"""
