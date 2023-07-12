#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: license_device_license_details_info
short_description: Information module for License Device License Details
description:
- Get all License Device License Details.
- Get detailed license information of a device.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  device_uuid:
    description:
    - Device_uuid path parameter. Id of device.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Licenses DeviceLicenseDetails2
  description: Complete reference of the DeviceLicenseDetails2 API.
  link: https://developer.cisco.com/docs/dna-center/#!device-license-details-2
notes:
  - SDK Method used are
    licenses.Licenses.device_license_details2,

  - Paths used are
    get /dna/intent/api/v1/licenses/device/{device_uuid}/details,

"""

EXAMPLES = r"""
- name: Get all License Device License Details
  cisco.dnac.license_device_license_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    device_uuid: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "device_uuid": "string",
        "site": "string",
        "model": "string",
        "license_mode": "string",
        "is_license_expired": true,
        "software_version": "string",
        "network_license": "string",
        "evaluation_license_expiry": "string",
        "device_name": "string",
        "device_type": "string",
        "dna_level": "string",
        "virtual_account_name": "string",
        "ip_address": "string",
        "mac_address": "string",
        "sntc_status": "string",
        "feature_license": [
          "string"
        ],
        "has_sup_cards": true,
        "udi": "string",
        "stacked_devices": [
          {
            "mac_address": "string",
            "id": "string",
            "role": "string",
            "serial_number": "string"
          }
        ],
        "is_stacked_device": true,
        "access_points": [
          {
            "ap_type": "string",
            "count": "string"
          }
        ],
        "chassis_details": {
          "board_serial_number": "string",
          "modules": [
            {
              "module_type": "string",
              "module_name": "string",
              "serial_number": "string",
              "id": "string"
            }
          ],
          "supervisor_cards": [
            {
              "serial_number": "string",
              "supervisor_card_type": "string",
              "status": "string"
            }
          ],
          "port": 0
        }
      }
    ]
"""
