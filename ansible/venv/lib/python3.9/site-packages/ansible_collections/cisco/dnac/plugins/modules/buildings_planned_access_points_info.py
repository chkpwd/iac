#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: buildings_planned_access_points_info
short_description: Information module for Buildings Planned Access Points
description:
- Get all Buildings Planned Access Points.
- Provides a list of Planned Access Points for the Building it is requested for.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  buildingId:
    description:
    - BuildingId path parameter. Building Id.
    type: str
  limit:
    description:
    - Limit query parameter.
    type: int
  offset:
    description:
    - Offset query parameter.
    type: int
  radios:
    description:
    - Radios query parameter. Inlcude planned radio details.
    type: bool
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices GetPlannedAccessPointsForBuilding
  description: Complete reference of the GetPlannedAccessPointsForBuilding API.
  link: https://developer.cisco.com/docs/dna-center/#!get-planned-access-points-for-building
notes:
  - SDK Method used are
    devices.Devices.get_planned_access_points_for_building,

  - Paths used are
    get /dna/intent/api/v1/buildings/{buildingId}/planned-access-points,

"""

EXAMPLES = r"""
- name: Get all Buildings Planned Access Points
  cisco.dnac.buildings_planned_access_points_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    limit: 0
    offset: 0
    radios: True
    buildingId: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "attributes": {
            "id": 0,
            "instanceUuid": "string",
            "name": "string",
            "typeString": "string",
            "domain": "string",
            "heirarchyName": "string",
            "source": "string",
            "createDate": 0,
            "macaddress": {}
          },
          "location": {},
          "position": {
            "x": 0,
            "y": 0,
            "z": 0
          },
          "radioCount": 0,
          "radios": [
            {
              "attributes": {
                "id": 0,
                "instanceUuid": "string",
                "slotId": 0,
                "ifTypeString": "string",
                "ifTypeSubband": "string",
                "channel": {},
                "channelString": {},
                "ifMode": "string"
              },
              "antenna": {
                "name": "string",
                "type": "string",
                "mode": "string",
                "azimuthAngle": 0,
                "elevationAngle": 0,
                "gain": 0
              },
              "isSensor": true
            }
          ],
          "isSensor": true
        }
      ],
      "version": 0,
      "total": 0
    }
"""
