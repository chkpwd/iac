#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pan_ha
short_description: Resource module for Pan Ha
description:
- Manage operations create and delete of the resource Pan Ha.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  failedAttempts:
    description: Pan Ha's failedAttempts.
    type: int
  isEnabled:
    description: IsEnabled flag.
    type: bool
  pollingInterval:
    description: Pan Ha's pollingInterval.
    type: int
  primaryHealthCheckNode:
    description: Pan Ha's primaryHealthCheckNode.
    type: str
  secondaryHealthCheckNode:
    description: Pan Ha's secondaryHealthCheckNode.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    sync_ise_node.ReplicationStatus.get_node_replication_status,

  - Paths used are
    get /api/v1/replication-status/{node}
"""

EXAMPLES = r"""
- name: Create
  cisco.ise.pan_ha:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    failedAttempts: 0
    isEnabled: true
    pollingInterval: 0
    primaryHealthCheckNode: string
    secondaryHealthCheckNode: string

- name: Delete all
  cisco.ise.pan_ha:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "isEnabled": true,
        "primaryHealthCheckNode": "string",
        "secondaryHealthCheckNode": "string",
        "pollingInterval": 0,
        "failedAttempts": 0
      }
    ]
"""
