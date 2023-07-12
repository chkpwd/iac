#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nfv_provision_details
short_description: Resource module for Nfv Provision Details
description:
- Manage operation create of the resource Nfv Provision Details.
- Checks the provisioning detail of an ENCS device including log information.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device_ip:
    description: Device Ip.
    type: str
  headers:
    description: Additional headers.
    type: dict
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Site Design NFVProvisioningDetail
  description: Complete reference of the NFVProvisioningDetail API.
  link: https://developer.cisco.com/docs/dna-center/#!n-fv-provisioning-detail
notes:
  - SDK Method used are
    site_design.SiteDesign.nfv_provisioning_detail,

  - Paths used are
    post /dna/intent/api/v1/nfv-provision-detail,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.nfv_provision_details:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    device_ip: string
    headers: '{{my_headers | from_json}}'

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
