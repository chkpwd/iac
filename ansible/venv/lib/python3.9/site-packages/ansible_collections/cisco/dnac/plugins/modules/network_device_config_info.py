#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_config_info
short_description: Information module for Network Device Config
description:
- Get all Network Device Config.
- Get Network Device Config by id.
- Returns the config for all devices.
- Returns the device config by specified device ID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
    - NetworkDeviceId path parameter.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices GetDeviceConfigById
  description: Complete reference of the GetDeviceConfigById API.
  link: https://developer.cisco.com/docs/dna-center/#!get-device-config-by-id
- name: Cisco DNA Center documentation for Devices GetDeviceConfigForAllDevices
  description: Complete reference of the GetDeviceConfigForAllDevices API.
  link: https://developer.cisco.com/docs/dna-center/#!get-device-config-for-all-devices
notes:
  - SDK Method used are
    devices.Devices.get_device_config_by_id,
    devices.Devices.get_device_config_for_all_devices,

  - Paths used are
    get /dna/intent/api/v1/network-device/config,
    get /dna/intent/api/v1/network-device/{networkDeviceId}/config,

"""

EXAMPLES = r"""
- name: Get all Network Device Config
  cisco.dnac.network_device_config_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result

- name: Get Network Device Config by id
  cisco.dnac.network_device_config_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": "string",
      "version": "string"
    }
"""
