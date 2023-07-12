#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_assign_device
short_description: Resource module for Site Assign Device
description:
- Manage operation create of the resource Site Assign Device.
- Assigns list of devices to a site.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device:
    description: Site Assign Device's device.
    elements: dict
    suboptions:
      ip:
        description: Device ip (eg 10.104.240.64).
        type: str
    type: list
  siteId:
    description: SiteId path parameter. Site id to which site the device to assign.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
notes:
  - SDK Method used are
    sites.Sites.assign_device_to_site,

  - Paths used are
    post /dna/system/api/v1/site/{siteId}/device,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.site_assign_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    device:
    - ip: string
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
