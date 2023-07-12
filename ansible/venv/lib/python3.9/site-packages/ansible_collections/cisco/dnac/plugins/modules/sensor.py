#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sensor
short_description: Resource module for Sensor
description:
- Manage operations create and delete of the resource Sensor.
- Intent API to create a SENSOR test template with a new SSID, existing SSID, or both new and existing SSID.
- Intent API to delete an existing SENSOR test template.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  apCoverage:
    description: Sensor's apCoverage.
    elements: dict
    suboptions:
      bands:
        description: Bands.
        type: str
      numberOfApsToTest:
        description: Number Of Aps To Test.
        type: str
      rssiThreshold:
        description: Rssi Threshold.
        type: str
    type: list
  connection:
    description: Connection.
    type: str
  modelVersion:
    description: Model Version.
    type: int
  name:
    description: Name.
    type: str
  ssids:
    description: Sensor's ssids.
    elements: dict
    suboptions:
      authType:
        description: Auth Type.
        type: str
      categories:
        description: Categories.
        elements: str
        type: list
      profileName:
        description: Profile Name.
        type: str
      psk:
        description: Psk.
        type: str
      qosPolicy:
        description: Qos Policy.
        type: str
      ssid:
        description: Ssid.
        type: str
      tests:
        description: Sensor's tests.
        elements: dict
        suboptions:
          config:
            description: Config.
            elements: dict
            type: list
          name:
            description: Name.
            type: str
        type: list
      thirdParty:
        description: Sensor's thirdParty.
        suboptions:
          selected:
            description: Selected.
            type: bool
        type: dict
    type: list
  templateName:
    description: TemplateName query parameter.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Sensors CreateSensorTestTemplate
  description: Complete reference of the CreateSensorTestTemplate API.
  link: https://developer.cisco.com/docs/dna-center/#!create-sensor-test-template
- name: Cisco DNA Center documentation for Sensors DeleteSensorTest
  description: Complete reference of the DeleteSensorTest API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-sensor-test
notes:
  - SDK Method used are
    sensors.Sensors.create_sensor_test_template,
    sensors.Sensors.delete_sensor_test,

  - Paths used are
    post /dna/intent/api/v1/sensor,
    delete /dna/intent/api/v1/sensor,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.sensor:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    apCoverage:
    - bands: string
      numberOfApsToTest: string
      rssiThreshold: string
    connection: string
    modelVersion: 0
    name: string
    ssids:
    - authType: string
      categories:
      - string
      profileName: string
      psk: string
      qosPolicy: string
      ssid: string
      tests:
      - config:
        - {}
        name: string
      thirdParty:
        selected: true

- name: Delete all
  cisco.dnac.sensor:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
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
          {}
        ],
        "schedule": {},
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
