#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: client_detail_info
short_description: Information module for Client Detail
description:
- Get all Client Detail.
- Returns detailed Client information retrieved by Mac Address for any given point of time.
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
    - Timestamp query parameter. Epoch time(in milliseconds) when the Client health data is required.
    type: str
  macAddress:
    description:
    - MacAddress query parameter. MAC Address of the client.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Clients GetClientDetail
  description: Complete reference of the GetClientDetail API.
  link: https://developer.cisco.com/docs/dna-center/#!get-client-detail
notes:
  - SDK Method used are
    clients.Clients.get_client_detail,

  - Paths used are
    get /dna/intent/api/v1/client-detail,

"""

EXAMPLES = r"""
- name: Get all Client Detail
  cisco.dnac.client_detail_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    timestamp: string
    macAddress: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "detail": {
        "id": "string",
        "connectionStatus": "string",
        "hostType": "string",
        "userId": {},
        "hostName": "string",
        "hostOs": {},
        "hostVersion": {},
        "subType": "string",
        "lastUpdated": 0,
        "healthScore": [
          {
            "healthType": "string",
            "reason": "string",
            "score": 0
          }
        ],
        "hostMac": "string",
        "hostIpV4": "string",
        "hostIpV6": [
          "string"
        ],
        "authType": "string",
        "vlanId": 0,
        "vnid": 0,
        "ssid": "string",
        "frequency": "string",
        "channel": "string",
        "apGroup": {},
        "location": {},
        "clientConnection": "string",
        "connectedDevice": [
          {}
        ],
        "issueCount": 0,
        "rssi": "string",
        "avgRssi": {},
        "snr": "string",
        "avgSnr": {},
        "dataRate": "string",
        "txBytes": "string",
        "rxBytes": "string",
        "dnsSuccess": {},
        "dnsFailure": {},
        "onboarding": {
          "averageRunDuration": {},
          "maxRunDuration": {},
          "averageAssocDuration": {},
          "maxAssocDuration": {},
          "averageAuthDuration": {},
          "maxAuthDuration": {},
          "averageDhcpDuration": {},
          "maxDhcpDuration": {},
          "aaaServerIp": "string",
          "dhcpServerIp": {},
          "authDoneTime": {},
          "assocDoneTime": {},
          "dhcpDoneTime": {},
          "assocRootcauseList": [
            {}
          ],
          "aaaRootcauseList": [
            {}
          ],
          "dhcpRootcauseList": [
            {}
          ],
          "otherRootcauseList": [
            {}
          ]
        },
        "clientType": "string",
        "onboardingTime": {},
        "port": {},
        "iosCapable": true
      },
      "connectionInfo": {
        "hostType": "string",
        "nwDeviceName": "string",
        "nwDeviceMac": "string",
        "protocol": "string",
        "band": "string",
        "spatialStream": "string",
        "channel": "string",
        "channelWidth": "string",
        "wmm": "string",
        "uapsd": "string",
        "timestamp": 0
      },
      "topology": {
        "nodes": [
          {
            "role": "string",
            "name": "string",
            "id": "string",
            "description": "string",
            "deviceType": "string",
            "platformId": {},
            "family": {},
            "ip": "string",
            "softwareVersion": {},
            "userId": {},
            "nodeType": "string",
            "radioFrequency": {},
            "clients": {},
            "count": {},
            "healthScore": 0,
            "level": 0,
            "fabricGroup": {},
            "connectedDevice": {}
          }
        ],
        "links": [
          {
            "source": "string",
            "linkStatus": "string",
            "label": [
              "string"
            ],
            "target": "string",
            "id": {},
            "portUtilization": {}
          }
        ]
      }
    }
"""
