#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_health_info
short_description: Information module for Site Health
description:
- Get all Site Health.
- Returns Overall Health information for all sites.
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
    - Timestamp query parameter. Epoch time(in milliseconds) when the Site Hierarchy data is required.
    type: str
  siteType:
    description:
    - SiteType query parameter. Type of the site to return. AREA or BUILDING. Default to AREA.
    type: str
  offset:
    description:
    - Offset query parameter. The offset value, starting from 1, of the first returned site entry. Default is 1.
    type: int
  limit:
    description:
    - Limit query parameter. The max number of sites in the returned data set. Default is 25, and max at 50.
    type: int
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Sites GetSiteHealth
  description: Complete reference of the GetSiteHealth API.
  link: https://developer.cisco.com/docs/dna-center/#!get-site-health
notes:
  - SDK Method used are
    sites.Sites.get_site_health,

  - Paths used are
    get /dna/intent/api/v1/site-health,

"""

EXAMPLES = r"""
- name: Get all Site Health
  cisco.dnac.site_health_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    timestamp: string
    siteType: string
    offset: 0
    limit: 0
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
        "siteName": "string",
        "siteId": "string",
        "parentSiteId": "string",
        "parentSiteName": "string",
        "siteType": "string",
        "latitude": 0,
        "longitude": 0,
        "healthyNetworkDevicePercentage": {},
        "healthyClientsPercentage": {},
        "clientHealthWired": {},
        "clientHealthWireless": {},
        "numberOfClients": {},
        "numberOfNetworkDevice": {},
        "networkHealthAverage": {},
        "networkHealthAccess": {},
        "networkHealthCore": {},
        "networkHealthDistribution": {},
        "networkHealthRouter": {},
        "networkHealthWireless": {},
        "networkHealthOthers": {},
        "numberOfWiredClients": {},
        "numberOfWirelessClients": {},
        "totalNumberOfConnectedWiredClients": {},
        "totalNumberOfActiveWirelessClients": {},
        "wiredGoodClients": {},
        "wirelessGoodClients": {},
        "overallGoodDevices": {},
        "accessGoodCount": {},
        "accessTotalCount": {},
        "coreGoodCount": {},
        "coreTotalCount": {},
        "distributionGoodCount": {},
        "distributionTotalCount": {},
        "routerGoodCount": {},
        "routerTotalCount": {},
        "wirelessDeviceGoodCount": {},
        "wirelessDeviceTotalCount": {},
        "applicationHealth": {},
        "applicationGoodCount": {},
        "applicationTotalCount": {},
        "applicationBytesTotalCount": {},
        "dnacInfo": {},
        "applicationHealthStats": {
          "appTotalCount": 0,
          "businessRelevantAppCount": {
            "poor": 0,
            "fair": 0,
            "good": 0
          },
          "businessIrrelevantAppCount": {
            "poor": 0,
            "fair": 0,
            "good": 0
          },
          "defaultHealthAppCount": {
            "poor": 0,
            "fair": 0,
            "good": 0
          }
        }
      }
    ]
"""
