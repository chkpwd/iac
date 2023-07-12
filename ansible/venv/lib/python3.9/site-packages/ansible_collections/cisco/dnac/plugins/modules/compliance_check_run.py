#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: compliance_check_run
short_description: Resource module for Compliance Check Run
description:
- Manage operation create of the resource Compliance Check Run.
- Run compliance check for devices.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  categories:
    description: Compliance Check Run's categories.
    elements: str
    type: list
  deviceUuids:
    description: Compliance Check Run's deviceUuids.
    elements: str
    type: list
  triggerFull:
    description: TriggerFull flag.
    type: bool
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Compliance RunCompliance
  description: Complete reference of the RunCompliance API.
  link: https://developer.cisco.com/docs/dna-center/#!run-compliance
notes:
  - SDK Method used are
    compliance.Compliance.run_compliance,

  - Paths used are
    post /dna/intent/api/v1/compliance/,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.compliance_check_run:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    categories:
    - string
    deviceUuids:
    - string
    triggerFull: true

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "taskId": "string",
        "url": "string"
      }
    }
"""
