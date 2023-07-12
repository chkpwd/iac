#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: compliance_device_by_id_info
short_description: Information module for Compliance Device By Id
description:
- Get all Compliance Device By Id.
- Return compliance detailed report for a device.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceUuid:
    description:
    - DeviceUuid path parameter.
    type: str
  category:
    description:
    - Category query parameter. ComplianceCategory can have any value among 'INTENT', 'RUNNING_CONFIG'.
    type: str
  complianceType:
    description:
    - >
      ComplianceType query parameter. ComplianceType can have any value among 'NETWORK_DESIGN', 'NETWORK_PROFILE',
      'FABRIC', 'POLICY', 'RUNNING_CONFIG'.
    type: str
  diffList:
    description:
    - DiffList query parameter. Diff list pass true to fetch the diff list.
    type: bool
  key:
    description:
    - Key query parameter. Extended attribute key.
    type: str
  value:
    description:
    - Value query parameter. Extended attribute value.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Compliance ComplianceDetailsOfDevice
  description: Complete reference of the ComplianceDetailsOfDevice API.
  link: https://developer.cisco.com/docs/dna-center/#!compliance-details-of-device
notes:
  - SDK Method used are
    compliance.Compliance.compliance_details_of_device,

  - Paths used are
    get /dna/intent/api/v1/compliance/{deviceUuid}/detail,

"""

EXAMPLES = r"""
- name: Get all Compliance Device By Id
  cisco.dnac.compliance_device_by_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    category: string
    complianceType: string
    diffList: True
    key: string
    value: string
    deviceUuid: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "deviceUuid": "string",
      "version": "string",
      "response": [
        {
          "displayName": "string",
          "complianceType": "string",
          "lastSyncTime": 0,
          "additionalDataURL": "string",
          "sourceInfoList": [
            {
              "count": 0,
              "displayName": "string",
              "diffList": [
                {
                  "displayName": "string",
                  "moveFromPath": "string",
                  "op": "string",
                  "configuredValue": "string",
                  "intendedValue": "string",
                  "path": "string",
                  "businessKey": "string",
                  "extendedAttributes": "string"
                }
              ],
              "sourceEnum": "string",
              "licenseAppName": "string",
              "provisioningArea": "string",
              "networkProfileName": "string",
              "nameWithBusinessKey": "string",
              "appName": "string",
              "name": "string",
              "type": "string",
              "businessKey": {
                "otherAttributes": {
                  "cfsAttributes": "string",
                  "name": "string"
                },
                "resourceName": "string",
                "businessKeyAttributes": "string"
              }
            }
          ],
          "deviceUuid": "string",
          "message": "string",
          "state": "string",
          "status": "string",
          "category": "string",
          "lastUpdateTime": 0
        }
      ]
    }
"""
