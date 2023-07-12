#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sensor_test_template_duplicate
short_description: Resource module for Sensor Test Template Duplicate
description:
- Manage operation update of the resource Sensor Test Template Duplicate.
- Intent API to duplicate an existing SENSOR test template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  newTemplateName:
    description: New Template Name.
    type: str
  templateName:
    description: Template Name.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Sensors DuplicateSensorTestTemplate
  description: Complete reference of the DuplicateSensorTestTemplate API.
  link: https://developer.cisco.com/docs/dna-center/#!duplicate-sensor-test-template
notes:
  - SDK Method used are
    sensors.Sensors.duplicate_sensor_test_template,

  - Paths used are
    put /dna/intent/api/v1/sensorTestTemplate,

"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.sensor_test_template_duplicate:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    newTemplateName: string
    templateName: string

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
        "_id": "string",
        "name": "string",
        "version": 0,
        "modelVersion": 0,
        "startTime": 0,
        "lastModifiedTime": 0,
        "numAssociatedSensor": 0,
        "location": {},
        "siteHierarchy": {},
        "status": "string",
        "connection": "string",
        "frequency": {},
        "rssiThreshold": 0,
        "numNeighborAPThreshold": 0,
        "scheduleInDays": 0,
        "wlans": [
          {}
        ],
        "ssids": [
          {
            "bands": {},
            "ssid": "string",
            "profileName": "string",
            "authType": "string",
            "authTypeRcvd": {},
            "psk": "string",
            "username": {},
            "password": {},
            "eapMethod": {},
            "scep": true,
            "authProtocol": {},
            "certfilename": {},
            "certxferprotocol": "string",
            "certstatus": "string",
            "certpassphrase": {},
            "certdownloadurl": {},
            "numAps": 0,
            "numSensors": 0,
            "layer3webAuthsecurity": {},
            "layer3webAuthuserName": {},
            "layer3webAuthpassword": {},
            "extWebAuthVirtualIp": {},
            "layer3webAuthEmailAddress": {},
            "qosPolicy": "string",
            "extWebAuth": true,
            "whiteList": true,
            "extWebAuthPortal": {},
            "extWebAuthAccessUrl": {},
            "extWebAuthHtmlTag": [
              {}
            ],
            "thirdParty": {
              "selected": true
            },
            "id": 0,
            "wlanId": 0,
            "wlc": {},
            "validFrom": 0,
            "validTo": 0,
            "status": "string",
            "tests": [
              {
                "name": "string",
                "config": [
                  {}
                ]
              }
            ]
          }
        ],
        "testScheduleMode": "string",
        "showWlcUpgradeBanner": true,
        "radioAsSensorRemoved": true,
        "encryptionMode": "string",
        "runNow": "string",
        "locationInfoList": [
          {
            "locationId": "string",
            "locationType": "string",
            "allSensors": true,
            "siteHierarchy": "string",
            "macAddressList": [
              {}
            ]
          }
        ],
        "schedule": {
          "testScheduleMode": "string",
          "scheduleRange": [
            {
              "timeRange": [
                {
                  "from": "string",
                  "to": "string",
                  "frequency": {
                    "value": 0,
                    "unit": "string"
                  }
                }
              ],
              "day": "string"
            }
          ],
          "startTime": 0,
          "frequency": {
            "value": 0,
            "unit": "string"
          }
        },
        "tests": {},
        "sensors": [
          {}
        ],
        "apCoverage": [
          {
            "bands": "string",
            "numberOfApsToTest": 0,
            "rssiThreshold": 0
          }
        ],
        "testDurationEstimate": 0,
        "testTemplate": true,
        "legacyTestSuite": true,
        "tenantId": {}
      }
    }
"""
