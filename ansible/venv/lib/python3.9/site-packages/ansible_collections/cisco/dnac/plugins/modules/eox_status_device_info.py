#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: eox_status_device_info
short_description: Information module for Eox Status Device
description:
- Get all Eox Status Device.
- Get Eox Status Device by id.
- Retrieves EoX details for a device.
- Retrieves EoX status for all devices in the network.
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceId:
    description:
    - DeviceId path parameter. Device instance UUID.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for EoX GetEoXDetailsPerDevice
  description: Complete reference of the GetEoXDetailsPerDevice API.
  link: https://developer.cisco.com/docs/dna-center/#!get-eo-x-details-per-device
- name: Cisco DNA Center documentation for EoX GetEoXStatusForAllDevices
  description: Complete reference of the GetEoXStatusForAllDevices API.
  link: https://developer.cisco.com/docs/dna-center/#!get-eo-x-status-for-all-devices
notes:
  - SDK Method used are
    eo_x.EoX.get_eo_x_details_per_device,
    eo_x.EoX.get_eo_x_status_for_all_devices,

  - Paths used are
    get /dna/intent/api/v1/eox-status/device,
    get /dna/intent/api/v1/eox-status/device/{deviceId},

"""

EXAMPLES = r"""
- name: Get all Eox Status Device
  cisco.dnac.eox_status_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
  register: result

- name: Get Eox Status Device by id
  cisco.dnac.eox_status_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceId: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "deviceId": "string",
        "alertCount": 0,
        "eoxDetails": [
          {
            "bulletinHeadline": "string",
            "bulletinNumber": "string",
            "bulletinURL": "string",
            "endOfHardwareNewServiceAttachmentDate": 0,
            "endOfHardwareServiceContractRenewalDate": 0,
            "endOfLastHardwareShipDate": 0,
            "endOfLifeDate": 0,
            "endOfLifeExternalAnnouncementDate": 0,
            "endOfSaleDate": 0,
            "endOfSignatureReleasesDate": 0,
            "endOfSoftwareVulnerabilityOrSecuritySupportDate": 0,
            "endOfSoftwareVulnerabilityOrSecuritySupportDateHw": 0,
            "endOfSoftwareMaintenanceReleasesDate": 0,
            "eoxAlertType": "string",
            "lastDateOfSupport": 0,
            "name": "string"
          }
        ],
        "scanStatus": "string",
        "comments": [
          {}
        ],
        "lastScanTime": 0
      },
      "version": "string"
    }
"""
