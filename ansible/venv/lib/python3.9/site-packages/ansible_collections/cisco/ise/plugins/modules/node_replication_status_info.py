#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_replication_status_info
short_description: Information module for Node Replication Status
description:
- Get Node Replication Status by id.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  node:
    description:
    - Node path parameter. ID of the existing node.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    replication_status.ReplicationStatus.get_node_replication_status,

  - Paths used are
    get /api/v1/replication-status/{node}
"""

EXAMPLES = r"""
- name: Get Node Replication Status by id
  cisco.ise.node_replication_status_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    node: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "NodeStatus": "string"
    }
"""
