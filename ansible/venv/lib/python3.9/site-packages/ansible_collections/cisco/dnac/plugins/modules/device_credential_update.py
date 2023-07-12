#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_credential_update
short_description: Resource module for Device Credential Update
description:
- Manage operation update of the resource Device Credential Update.
- API to update device credentials.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  settings:
    description: Device Credential Update's settings.
    suboptions:
      cliCredential:
        description: Device Credential Update's cliCredential.
        suboptions:
          description:
            description: Description.
            type: str
          enablePassword:
            description: Enable Password.
            type: str
          id:
            description: Id.
            type: str
          password:
            description: Password.
            type: str
          username:
            description: Username.
            type: str
        type: dict
      httpsRead:
        description: Device Credential Update's httpsRead.
        suboptions:
          id:
            description: Id.
            type: str
          name:
            description: Name.
            type: str
          password:
            description: Password.
            type: str
          port:
            description: Port.
            type: str
          username:
            description: Username.
            type: str
        type: dict
      httpsWrite:
        description: Device Credential Update's httpsWrite.
        suboptions:
          id:
            description: Id.
            type: str
          name:
            description: Name.
            type: str
          password:
            description: Password.
            type: str
          port:
            description: Port.
            type: str
          username:
            description: Username.
            type: str
        type: dict
      snmpV2cRead:
        description: Device Credential Update's snmpV2cRead.
        suboptions:
          description:
            description: Description.
            type: str
          id:
            description: Id.
            type: str
          readCommunity:
            description: Read Community.
            type: str
        type: dict
      snmpV2cWrite:
        description: Device Credential Update's snmpV2cWrite.
        suboptions:
          description:
            description: Description.
            type: str
          id:
            description: Id.
            type: str
          writeCommunity:
            description: Write Community.
            type: str
        type: dict
      snmpV3:
        description: Device Credential Update's snmpV3.
        suboptions:
          authPassword:
            description: Auth Password.
            type: str
          authType:
            description: Auth Type.
            type: str
          description:
            description: Description.
            type: str
          id:
            description: Id.
            type: str
          privacyPassword:
            description: Privacy Password.
            type: str
          privacyType:
            description: Privacy Type.
            type: str
          snmpMode:
            description: Snmp Mode.
            type: str
          username:
            description: Username.
            type: str
        type: dict
    type: dict
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Network Settings UpdateDeviceCredentials
  description: Complete reference of the UpdateDeviceCredentials API.
  link: https://developer.cisco.com/docs/dna-center/#!update-device-credentials
notes:
  - SDK Method used are
    network_settings.NetworkSettings.update_device_credentials,

  - Paths used are
    put /dna/intent/api/v1/device-credential,

"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.device_credential_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    settings:
      cliCredential:
        description: string
        enablePassword: string
        id: string
        password: string
        username: string
      httpsRead:
        id: string
        name: string
        password: string
        port: string
        username: string
      httpsWrite:
        id: string
        name: string
        password: string
        port: string
        username: string
      snmpV2cRead:
        description: string
        id: string
        readCommunity: string
      snmpV2cWrite:
        description: string
        id: string
        writeCommunity: string
      snmpV3:
        authPassword: string
        authType: string
        description: string
        id: string
        privacyPassword: string
        privacyType: string
        snmpMode: string
        username: string

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
