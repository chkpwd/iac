#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_details_info
short_description: Information module for Device Details
description:
- Get all Device Details.
- Returns detailed Network Device information retrieved by Mac Address, Device Name or UUID for any given point of time.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  timestamp:
    description:
    - Timestamp query parameter. Epoch time(in milliseconds) when the device data is required.
    type: str
  searchBy:
    description:
    - SearchBy query parameter. MAC Address or Device Name value or UUID of the network device.
    type: str
  identifier:
    description:
    - Identifier query parameter. One of keywords macAddress or uuid or nwDeviceName.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices GetDeviceDetail
  description: Complete reference of the GetDeviceDetail API.
  link: https://developer.cisco.com/docs/dna-center/#!get-device-detail
notes:
  - SDK Method used are
    devices.Devices.get_device_detail,

  - Paths used are
    get /dna/intent/api/v1/device-detail,

"""

EXAMPLES = r"""
- name: Get all Device Details
  cisco.dnac.device_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    timestamp: string
    searchBy: string
    identifier: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "HALastResetReason": "string",
      "managementIpAddr": "string",
      "HAPrimaryPowerStatus": "string",
      "redundancyMode": "string",
      "communicationState": "string",
      "nwDeviceName": "string",
      "redundancyUnit": "string",
      "platformId": "string",
      "redundancyPeerState": "string",
      "nwDeviceId": "string",
      "redundancyState": "string",
      "nwDeviceRole": "string",
      "nwDeviceFamily": "string",
      "macAddress": "string",
      "collectionStatus": "string",
      "deviceSeries": "string",
      "osType": "string",
      "clientCount": "string",
      "HASecondaryPowerStatus": "string",
      "softwareVersion": "string",
      "nwDeviceType": "string",
      "overallHealth": 0,
      "memoryScore": 0,
      "cpuScore": 0,
      "noiseScore": 0,
      "utilizationScore": 0,
      "airQualityScore": 0,
      "interferenceScore": 0,
      "wqeScore": 0,
      "freeMbufScore": 0,
      "packetPoolScore": 0,
      "freeTimerScore": 0,
      "memory": "string",
      "cpu": "string",
      "noise": "string",
      "utilization": "string",
      "airQuality": "string",
      "interference": "string",
      "wqe": "string",
      "freeMbuf": "string",
      "packetPool": "string",
      "freeTimer": "string",
      "location": "string",
      "timestamp": "string"
    }
"""
