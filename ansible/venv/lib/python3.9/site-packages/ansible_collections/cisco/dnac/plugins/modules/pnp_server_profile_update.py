#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_server_profile_update
short_description: Resource module for Pnp Server Profile Update
description:
- Manage operation update of the resource Pnp Server Profile Update.
- >
   Updates the PnP Server profile in a registered Virtual Account in the PnP database. The response payload returns
   the updated smart & virtual account info.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  autoSyncPeriod:
    description: Pnp Server Profile Update's autoSyncPeriod.
    type: int
  ccoUser:
    description: Pnp Server Profile Update's ccoUser.
    type: str
  expiry:
    description: Pnp Server Profile Update's expiry.
    type: int
  lastSync:
    description: Pnp Server Profile Update's lastSync.
    type: int
  profile:
    description: Pnp Server Profile Update's profile.
    suboptions:
      addressFqdn:
        description: Pnp Server Profile Update's addressFqdn.
        type: str
      addressIpV4:
        description: Pnp Server Profile Update's addressIpV4.
        type: str
      cert:
        description: Pnp Server Profile Update's cert.
        type: str
      makeDefault:
        description: MakeDefault flag.
        type: bool
      name:
        description: Pnp Server Profile Update's name.
        type: str
      port:
        description: Pnp Server Profile Update's port.
        type: int
      profileId:
        description: Pnp Server Profile Update's profileId.
        type: str
      proxy:
        description: Proxy flag.
        type: bool
    type: dict
  smartAccountId:
    description: Pnp Server Profile Update's smartAccountId.
    type: str
  syncResult:
    description: Pnp Server Profile Update's syncResult.
    suboptions:
      syncList:
        description: Pnp Server Profile Update's syncList.
        elements: dict
        suboptions:
          deviceSnList:
            description: Pnp Server Profile Update's deviceSnList.
            elements: str
            type: list
          syncType:
            description: Pnp Server Profile Update's syncType.
            type: str
        type: list
      syncMsg:
        description: Pnp Server Profile Update's syncMsg.
        type: str
    type: dict
  syncResultStr:
    description: Pnp Server Profile Update's syncResultStr.
    type: str
  syncStartTime:
    description: Pnp Server Profile Update's syncStartTime.
    type: int
  syncStatus:
    description: Pnp Server Profile Update's syncStatus.
    type: str
  tenantId:
    description: Pnp Server Profile Update's tenantId.
    type: str
  token:
    description: Pnp Server Profile Update's token.
    type: str
  virtualAccountId:
    description: Pnp Server Profile Update's virtualAccountId.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Device Onboarding (PnP) UpdatePnPServerProfile
  description: Complete reference of the UpdatePnPServerProfile API.
  link: https://developer.cisco.com/docs/dna-center/#!update-pn-p-server-profile
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.update_pnp_server_profile,

  - Paths used are
    put /dna/intent/api/v1/onboarding/pnp-settings/savacct,

"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.pnp_server_profile_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    autoSyncPeriod: 0
    ccoUser: string
    expiry: 0
    lastSync: 0
    profile:
      addressFqdn: string
      addressIpV4: string
      cert: string
      makeDefault: true
      name: string
      port: 0
      profileId: string
      proxy: true
    smartAccountId: string
    syncResult:
      syncList:
      - deviceSnList:
        - string
        syncType: string
      syncMsg: string
    syncResultStr: string
    syncStartTime: 0
    syncStatus: string
    tenantId: string
    token: string
    virtualAccountId: string

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "virtualAccountId": "string",
      "autoSyncPeriod": 0,
      "syncResultStr": "string",
      "profile": {
        "proxy": true,
        "makeDefault": true,
        "port": 0,
        "profileId": "string",
        "name": "string",
        "addressIpV4": "string",
        "cert": "string",
        "addressFqdn": "string"
      },
      "ccoUser": "string",
      "syncResult": {
        "syncList": [
          {
            "syncType": "string",
            "deviceSnList": [
              "string"
            ]
          }
        ],
        "syncMsg": "string"
      },
      "token": "string",
      "syncStartTime": 0,
      "lastSync": 0,
      "tenantId": "string",
      "smartAccountId": "string",
      "expiry": 0,
      "syncStatus": "string"
    }
"""
