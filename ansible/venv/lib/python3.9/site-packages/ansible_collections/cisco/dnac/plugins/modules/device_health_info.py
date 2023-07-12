#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_health_info
short_description: Information module for Device Health
description:
- Get all Device Health.
- >
   Intent API for accessing DNA Assurance Device object for generating reports, creating dashboards or creating
   additional value added services.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceRole:
    description:
    - DeviceRole query parameter. The device role (One of CORE, ACCESS, DISTRIBUTION, ROUTER, WLC, AP).
    type: str
  siteId:
    description:
    - SiteId query parameter. Assurance site UUID value.
    type: str
  health:
    description:
    - Health query parameter. The device overall health (One of POOR, FAIR, GOOD).
    type: str
  startTime:
    description:
    - StartTime query parameter. UTC epoch time in milliseconds.
    type: int
  endTime:
    description:
    - EndTime query parameter. UTC epoch time in miliseconds.
    type: int
  limit:
    description:
    - Limit query parameter. Max number of device entries in the response (default to 50. Max at 1000).
    type: int
  offset:
    description:
    - Offset query parameter. The offset of the first device in the returned data.
    type: int
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices Devices
  description: Complete reference of the Devices API.
  link: https://developer.cisco.com/docs/dna-center/#!api-devices-devices
notes:
  - SDK Method used are
    devices.Devices.devices,

  - Paths used are
    get /dna/intent/api/v1/device-health,

"""

EXAMPLES = r"""
- name: Get all Device Health
  cisco.dnac.device_health_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceRole: string
    siteId: string
    health: string
    startTime: 0
    endTime: 0
    limit: 0
    offset: 0
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "totalCount": 0,
      "response": [
        {
          "name": "string",
          "model": "string",
          "osVersion": "string",
          "ipAddress": "string",
          "overallHealth": 0,
          "issueCount": 0,
          "location": "string",
          "deviceFamily": "string",
          "deviceType": "string",
          "macAddress": "string",
          "interfaceLinkErrHealth": 0,
          "cpuUlitilization": 0,
          "cpuHealth": 0,
          "memoryUtilizationHealth": 0,
          "memoryUtilization": 0,
          "interDeviceLinkAvailHealth": 0,
          "reachabilityHealth": "string",
          "clientCount": {
            "radio0": 0,
            "radio1": 0,
            "Ghz24": 0,
            "Ghz50": 0
          },
          "interferenceHealth": {
            "radio0": 0,
            "radio1": 0,
            "Ghz24": 0,
            "Ghz50": 0
          },
          "noiseHealth": {
            "radio1": 0,
            "Ghz50": 0
          },
          "airQualityHealth": {
            "radio0": 0,
            "radio1": 0,
            "Ghz24": 0,
            "Ghz50": 0
          },
          "utilizationHealth": {
            "radio0": 0,
            "radio1": 0,
            "Ghz24": 0,
            "Ghz50": 0
          }
        }
      ]
    }
"""
