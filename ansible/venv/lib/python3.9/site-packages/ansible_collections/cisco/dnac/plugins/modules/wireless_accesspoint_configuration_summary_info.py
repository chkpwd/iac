#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_accesspoint_configuration_summary_info
short_description: Information module for Wireless Accesspoint Configuration Summary
description:
- Get all Wireless Accesspoint Configuration Summary.
- Users can query the access point configuration information per device using the ethernet MAC address.
version_added: '6.7.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  key:
    description:
    - Key query parameter. The ethernet MAC address of Access point.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Wireless GetAccessPointConfiguration
  description: Complete reference of the GetAccessPointConfiguration API.
  link: https://developer.cisco.com/docs/dna-center/#!get-access-point-configuration
notes:
  - SDK Method used are
    wireless.Wireless.get_access_point_configuration,

  - Paths used are
    get /dna/intent/api/v1/wireless/accesspoint-configuration/summary,

"""

EXAMPLES = r"""
- name: Get all Wireless Accesspoint Configuration Summary
  cisco.dnac.wireless_accesspoint_configuration_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    key: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "instanceUuid": {},
      "instanceId": 0,
      "authEntityId": {},
      "displayName": "string",
      "authEntityClass": {},
      "instanceTenantId": "string",
      "_orderedListOEIndex": 0,
      "_orderedListOEAssocName": {},
      "_creationOrderIndex": 0,
      "_isBeingChanged": true,
      "deployPending": "string",
      "instanceCreatedOn": {},
      "instanceUpdatedOn": {},
      "changeLogList": {},
      "instanceOrigin": {},
      "lazyLoadedEntities": {},
      "instanceVersion": 0,
      "adminStatus": "string",
      "apHeight": 0,
      "apMode": "string",
      "apName": "string",
      "ethMac": "string",
      "failoverPriority": "string",
      "ledBrightnessLevel": 0,
      "ledStatus": "string",
      "location": "string",
      "macAddress": "string",
      "primaryControllerName": "string",
      "primaryIpAddress": "string",
      "secondaryControllerName": "string",
      "secondaryIpAddress": "string",
      "tertiaryControllerName": "string",
      "tertiaryIpAddress": "string",
      "meshDTOs": [
        {}
      ],
      "radioDTOs": [
        {
          "instanceUuid": {},
          "instanceId": 0,
          "authEntityId": {},
          "displayName": "string",
          "authEntityClass": {},
          "instanceTenantId": "string",
          "_orderedListOEIndex": 0,
          "_orderedListOEAssocName": {},
          "_creationOrderIndex": 0,
          "_isBeingChanged": true,
          "deployPending": "string",
          "instanceCreatedOn": {},
          "instanceUpdatedOn": {},
          "changeLogList": {},
          "instanceOrigin": {},
          "lazyLoadedEntities": {},
          "instanceVersion": 0,
          "adminStatus": "string",
          "antennaAngle": 0,
          "antennaElevAngle": 0,
          "antennaGain": 0,
          "antennaPatternName": "string",
          "channelAssignmentMode": "string",
          "channelNumber": 0,
          "channelWidth": "string",
          "cleanAirSI": "string",
          "ifType": 0,
          "ifTypeValue": "string",
          "macAddress": "string",
          "powerAssignmentMode": "string",
          "powerlevel": 0,
          "radioBand": {},
          "radioRoleAssignment": {},
          "slotId": 0,
          "internalKey": {
            "type": "string",
            "id": 0,
            "longType": "string",
            "url": "string"
          }
        }
      ],
      "internalKey": {
        "type": "string",
        "id": 0,
        "longType": "string",
        "url": "string"
      }
    }
"""
