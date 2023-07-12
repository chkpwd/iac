#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assign_device_to_site
short_description: Resource module for Assign Device To Site
description:
- Manage operation create of the resource Assign Device To Site.
- Assigns unassigned devices to a site. This API does not move assigned devices to other sites.
version_added: '6.5.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device:
    description: Assign Device To Site's device.
    elements: dict
    suboptions:
      ip:
        description: Device ip (eg 10.104.240.64).
        type: str
    type: list
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description: SiteId path parameter. Site id to which site the device to assign.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for  AssignDevicesToSite
  description: Complete reference of the AssignDevicesToSite API.
  link: https://developer.cisco.com/docs/dna-center/#!assign-devices-to-site
notes:
  - SDK Method used are
    ..assign_devices_to_site,

  - Paths used are
    post /dna/intent/api/v1/assign-device-to-site/{siteId}/device,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.assign_device_to_site:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    device:
    - ip: string
    headers: '{{my_headers | from_json}}'
    siteId: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
