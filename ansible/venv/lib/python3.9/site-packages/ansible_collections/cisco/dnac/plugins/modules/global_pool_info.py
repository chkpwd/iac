#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: global_pool_info
short_description: Information module for Global Pool
description:
- Get all Global Pool.
- API to get global pool.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  offset:
    description:
    - Offset query parameter. Offset/starting row.
    type: int
  limit:
    description:
    - Limit query parameter. No of Global Pools to be retrieved.
    type: int
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Network Settings GetGlobalPool
  description: Complete reference of the GetGlobalPool API.
  link: https://developer.cisco.com/docs/dna-center/#!get-global-pool
notes:
  - SDK Method used are
    network_settings.NetworkSettings.get_global_pool,

  - Paths used are
    get /dna/intent/api/v1/global-pool,

"""

EXAMPLES = r"""
- name: Get all Global Pool
  cisco.dnac.global_pool_info:
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
          "ipPoolName": "string",
          "dhcpServerIps": [
            "string"
          ],
          "gateways": [
            "string"
          ],
          "createTime": "string",
          "lastUpdateTime": "string",
          "totalIpAddressCount": "string",
          "usedIpAddressCount": "string",
          "parentUuid": "string",
          "owner": "string",
          "shared": "string",
          "overlapping": "string",
          "configureExternalDhcp": "string",
          "usedPercentage": "string",
          "clientOptions": {},
          "dnsServerIps": [
            "string"
          ],
          "context": [
            {
              "owner": "string",
              "contextKey": "string",
              "contextValue": "string"
            }
          ],
          "ipv6": "string",
          "id": "string",
          "ipPoolCidr": "string"
        }
      ],
      "version": "string"
    }
"""
