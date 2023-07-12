#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: device_credential_create
short_description: Resource module for Device Credential Create
description:
- Manage operation create of the resource Device Credential Create.
- API to create device credentials.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  settings:
    description: Device Credential Create's settings.
    suboptions:
      cliCredential:
        description: Device Credential Create's cliCredential.
        elements: dict
        suboptions:
          description:
            description: Name or description for CLI credential.
            type: str
          enablePassword:
            description: Enable password for CLI credential.
            type: str
          password:
            description: Password for CLI credential.
            type: str
          username:
            description: User name for CLI credential.
            type: str
        type: list
      httpsRead:
        description: Device Credential Create's httpsRead.
        elements: dict
        suboptions:
          name:
            description: Name or description of http read credential.
            type: str
          password:
            description: Password for http read credential.
            type: str
          port:
            description: Port for http read credential.
            type: int
          username:
            description: User name of the http read credential.
            type: str
        type: list
      httpsWrite:
        description: Device Credential Create's httpsWrite.
        elements: dict
        suboptions:
          name:
            description: Name or description of http write credential.
            type: str
          password:
            description: Password for http write credential.
            type: str
          port:
            description: Port for http write credential.
            type: int
          username:
            description: User name of the http write credential.
            type: str
        type: list
      snmpV2cRead:
        description: Device Credential Create's snmpV2cRead.
        elements: dict
        suboptions:
          description:
            description: Description for snmp v2 read.
            type: str
          readCommunity:
            description: Ready community for snmp v2 read credential.
            type: str
        type: list
      snmpV2cWrite:
        description: Device Credential Create's snmpV2cWrite.
        elements: dict
        suboptions:
          description:
            description: Description for snmp v2 write.
            type: str
          writeCommunity:
            description: Write community for snmp v2 write credential.
            type: str
        type: list
      snmpV3:
        description: Device Credential Create's snmpV3.
        elements: dict
        suboptions:
          authPassword:
            description: Authentication password for snmpv3 credential.
            type: str
          authType:
            description: Authentication type for snmpv3 credential.
            type: str
          description:
            description: Name or description for SNMPV3 credential.
            type: str
          privacyPassword:
            description: Privacy password for snmpv3 credential.
            type: str
          privacyType:
            description: Privacy type for snmpv3 credential.
            type: str
          snmpMode:
            description: Mode for snmpv3 credential.
            type: str
          username:
            description: User name for SNMPv3 credential.
            type: str
        type: list
    type: dict
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Network Settings CreateDeviceCredentials
  description: Complete reference of the CreateDeviceCredentials API.
  link: https://developer.cisco.com/docs/dna-center/#!create-device-credentials
notes:
  - SDK Method used are
    network_settings.NetworkSettings.create_device_credentials,

  - Paths used are
    post /dna/intent/api/v1/device-credential,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.device_credential_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    settings:
      cliCredential:
      - description: string
        enablePassword: string
        password: string
        username: string
      httpsRead:
      - name: string
        password: string
        port: 0
        username: string
      httpsWrite:
      - name: string
        password: string
        port: 0
        username: string
      snmpV2cRead:
      - description: string
        readCommunity: string
      snmpV2cWrite:
      - description: string
        writeCommunity: string
      snmpV3:
      - authPassword: string
        authType: string
        description: string
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
