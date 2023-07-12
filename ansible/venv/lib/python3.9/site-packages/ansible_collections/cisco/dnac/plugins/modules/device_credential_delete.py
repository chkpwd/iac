#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_credential_delete
short_description: Resource module for Device Credential Delete
description:
- Manage operation delete of the resource Device Credential Delete.
- Delete device credential.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Global credential id.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Network Settings DeleteDeviceCredential
  description: Complete reference of the DeleteDeviceCredential API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-device-credential
notes:
  - SDK Method used are
    network_settings.NetworkSettings.delete_device_credential,

  - Paths used are
    delete /dna/intent/api/v1/device-credential/{id},

"""

EXAMPLES = r"""
- name: Delete by id
  cisco.dnac.device_credential_delete:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    id: string

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
