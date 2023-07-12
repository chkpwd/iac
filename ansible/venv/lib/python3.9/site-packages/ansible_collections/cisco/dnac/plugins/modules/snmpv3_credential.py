#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: snmpv3_credential
short_description: Resource module for Snmpv3 Credential
description:
- Manage operations create and update of the resource Snmpv3 Credential.
- Adds global SNMPv3 credentials.
- Updates global SNMPv3 credential.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  authPassword:
    description: Snmpv3 Credential's authPassword.
    type: str
  authType:
    description: Snmpv3 Credential's authType.
    type: str
  comments:
    description: Snmpv3 Credential's comments.
    type: str
  credentialType:
    description: Snmpv3 Credential's credentialType.
    type: str
  description:
    description: Snmpv3 Credential's description.
    type: str
  id:
    description: Snmpv3 Credential's id.
    type: str
  instanceTenantId:
    description: Snmpv3 Credential's instanceTenantId.
    type: str
  instanceUuid:
    description: Snmpv3 Credential's instanceUuid.
    type: str
  privacyPassword:
    description: Snmpv3 Credential's privacyPassword.
    type: str
  privacyType:
    description: Snmpv3 Credential's privacyType.
    type: str
  snmpMode:
    description: Snmpv3 Credential's snmpMode.
    type: str
  username:
    description: Snmpv3 Credential's username.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Discovery CreateSNMPv3Credentials
  description: Complete reference of the CreateSNMPv3Credentials API.
  link: https://developer.cisco.com/docs/dna-center/#!create-snm-pv-3-credentials
- name: Cisco DNA Center documentation for Discovery UpdateSNMPv3Credentials
  description: Complete reference of the UpdateSNMPv3Credentials API.
  link: https://developer.cisco.com/docs/dna-center/#!update-snm-pv-3-credentials
notes:
  - SDK Method used are
    discovery.Discovery.create_snmpv3_credentials,
    discovery.Discovery.update_snmpv3_credentials,

  - Paths used are
    post /dna/intent/api/v1/global-credential/snmpv3,
    put /dna/intent/api/v1/global-credential/snmpv3,

"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.snmpv3_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    authPassword: string
    authType: string
    comments: string
    credentialType: string
    description: string
    id: string
    instanceTenantId: string
    instanceUuid: string
    privacyPassword: string
    privacyType: string
    snmpMode: string
    username: string

- name: Create
  cisco.dnac.snmpv3_credential:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    authPassword: string
    authType: string
    comments: string
    credentialType: string
    description: string
    id: string
    instanceTenantId: string
    instanceUuid: string
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
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
