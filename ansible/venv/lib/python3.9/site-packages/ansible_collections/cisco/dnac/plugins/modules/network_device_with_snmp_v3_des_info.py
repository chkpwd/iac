#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_with_snmp_v3_des_info
short_description: Information module for Network Device With Snmp V3 Des
description:
- Get all Network Device With Snmp V3 Des.
- >
   Returns devices added to Cisco DNA center with snmp v3 DES, where siteId is mandatory & accepts offset, limit,
   sortby, order which are optional.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
    - SiteId path parameter.
    type: str
  offset:
    description:
    - Offset query parameter. Row Number. Default value is 1.
    type: int
  limit:
    description:
    - Limit query parameter. Default value is 500.
    type: int
  sortBy:
    description:
    - SortBy query parameter. Sort By.
    type: str
  order:
    description:
    - Order query parameter.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices ReturnsDevicesAddedToCiscoDNACenterWithSnmpV3DES
  description: Complete reference of the ReturnsDevicesAddedToCiscoDNACenterWithSnmpV3DES API.
  link: https://developer.cisco.com/docs/dna-center/#!returns-devices-added-to-cisco-dna-center-with-snmp-v-3-des
notes:
  - SDK Method used are
    devices.Devices.get_devices_with_snmpv3_des,

  - Paths used are
    get /dna/intent/api/v1/network-device/insight/{siteId}/insecure-connection,

"""

EXAMPLES = r"""
- name: Get all Network Device With Snmp V3 Des
  cisco.dnac.network_device_with_snmp_v3_des_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    offset: 0
    limit: 0
    sortBy: string
    order: string
    siteId: string
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
          "id": "string",
          "managementIpAddress": "string",
          "hostname": "string",
          "type": "string",
          "family": "string",
          "lastUpdated": "string",
          "upTime": "string",
          "reachabilityStatus": "string"
        }
      ],
      "version": "string"
    }
"""
