#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_export
short_description: Resource module for Network Device Export
description:
- Manage operation create of the resource Network Device Export.
- Exports the selected network device to a file.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceUuids:
    description: Network Device Export's deviceUuids.
    elements: str
    type: list
  id:
    description: Network Device Export's id.
    type: str
  operationEnum:
    description: Network Device Export's operationEnum.
    type: str
  parameters:
    description: Network Device Export's parameters.
    elements: str
    type: list
  password:
    description: Network Device Export's password.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices ExportDeviceList
  description: Complete reference of the ExportDeviceList API.
  link: https://developer.cisco.com/docs/dna-center/#!export-device-list
notes:
  - SDK Method used are
    devices.Devices.export_device_list,

  - Paths used are
    post /dna/intent/api/v1/network-device/file,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.network_device_export:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceUuids:
    - string
    id: string
    operationEnum: string
    parameters:
    - string
    password: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
