#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric
short_description: Resource module for Sda Fabric
description:
- Manage operations create and delete of the resource Sda Fabric.
- Add SDA Fabric.
- Delete SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  fabricName:
    description: FabricName query parameter. Fabric Name.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
notes:
  - SDK Method used are
    sda.Sda.add_fabric,
    sda.Sda.delete_sda_fabric,

  - Paths used are
    post /dna/intent/api/v1/business/sda/fabric,
    delete /dna/intent/api/v1/business/sda/fabric,

"""

EXAMPLES = r"""
- name: Delete all
  cisco.dnac.sda_fabric:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    fabricName: string

- name: Create
  cisco.dnac.sda_fabric:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    fabricName: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "taskId": "string",
      "taskStatusUrl": "string",
      "executionStatusUrl": "string",
      "executionId": "string"
    }
"""
