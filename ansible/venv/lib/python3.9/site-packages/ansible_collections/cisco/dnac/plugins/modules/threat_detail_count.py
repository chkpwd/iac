#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: threat_detail_count
short_description: Resource module for Threat Detail Count
description:
- Manage operation create of the resource Threat Detail Count.
- The details count for the Rogue and aWIPS threats.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  endTime:
    description: End Time.
    type: int
  isNewThreat:
    description: Is New Threat.
    type: bool
  limit:
    description: Limit.
    type: int
  offset:
    description: Offset.
    type: int
  siteId:
    description: Site Id.
    elements: str
    type: list
  startTime:
    description: Start Time.
    type: int
  threatLevel:
    description: Threat Level.
    elements: str
    type: list
  threatType:
    description: Threat Type.
    elements: str
    type: list
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
notes:
  - SDK Method used are
    devices.Devices.threat_detail_count,

  - Paths used are
    post /dna/intent/api/v1/security/threats/details/count,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.threat_detail_count:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    endTime: 0
    isNewThreat: true
    limit: 0
    offset: 0
    siteId:
    - string
    startTime: 0
    threatLevel:
    - string
    threatType:
    - string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0,
      "version": "string"
    }
"""
