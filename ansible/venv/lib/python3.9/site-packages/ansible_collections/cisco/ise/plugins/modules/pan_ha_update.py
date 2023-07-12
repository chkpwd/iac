#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pan_ha_update
short_description: Resource module for Pan Ha Update
description:
- Manage operation update of the resource Pan Ha Update.
- To deploy the auto-failover feature, you must have at least three nodes, where.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  failedAttempts:
    description: Failover occurs if the primary PAN is down for the specified number
      of failure polls. Count (2 - 60).<br> The default value is 5.
    type: int
  isEnabled:
    description: IsEnabled flag.
    type: bool
  pollingInterval:
    description: Administration nodes are checked after each interval. Seconds (30 -
      300) <br> The default value is 120.
    type: int
  primaryHealthCheckNode:
    description: Pan Ha Update's primaryHealthCheckNode.
    suboptions:
      hostname:
        description: Pan Ha Update's hostname.
        type: str
    type: dict
  secondaryHealthCheckNode:
    description: Pan Ha Update's secondaryHealthCheckNode.
    suboptions:
      hostname:
        description: Pan Ha Update's hostname.
        type: str
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for PAN HA
  description: Complete reference of the PAN HA API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    pan_ha.PanHa.update_pan_ha,

  - Paths used are
    put /api/v1/deployment/pan-ha,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.pan_ha_update:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    failedAttempts: 0
    isEnabled: true
    pollingInterval: 0
    primaryHealthCheckNode:
      hostname: string
    secondaryHealthCheckNode:
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
