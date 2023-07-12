#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_global_settings
short_description: Resource module for Pnp Global Settings
description:
- Manage operation update of the resource Pnp Global Settings.
- Updates the user's list of global PnP settings.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  _id:
    description: Pnp Global Settings's _id.
    type: str
  aaaCredentials:
    description: Pnp Global Settings's aaaCredentials.
    suboptions:
      password:
        description: Pnp Global Settings's password.
        type: str
      username:
        description: Pnp Global Settings's username.
        type: str
    type: dict
  acceptEula:
    description: AcceptEula flag.
    type: bool
  defaultProfile:
    description: Pnp Global Settings's defaultProfile.
    suboptions:
      cert:
        description: Pnp Global Settings's cert.
        type: str
      fqdnAddresses:
        description: Pnp Global Settings's fqdnAddresses.
        elements: str
        type: list
      ipAddresses:
        description: Pnp Global Settings's ipAddresses.
        elements: str
        type: list
      port:
        description: Pnp Global Settings's port.
        type: int
      proxy:
        description: Proxy flag.
        type: bool
    type: dict
  savaMappingList:
    description: Pnp Global Settings's savaMappingList.
    elements: dict
    suboptions:
      autoSyncPeriod:
        description: Pnp Global Settings's autoSyncPeriod.
        type: int
      ccoUser:
        description: Pnp Global Settings's ccoUser.
        type: str
      expiry:
        description: Pnp Global Settings's expiry.
        type: int
      lastSync:
        description: Pnp Global Settings's lastSync.
        type: int
      profile:
        description: Pnp Global Settings's profile.
        suboptions:
          addressFqdn:
            description: Pnp Global Settings's addressFqdn.
            type: str
          addressIpV4:
            description: Pnp Global Settings's addressIpV4.
            type: str
          cert:
            description: Pnp Global Settings's cert.
            type: str
          makeDefault:
            description: MakeDefault flag.
            type: bool
          name:
            description: Pnp Global Settings's name.
            type: str
          port:
            description: Pnp Global Settings's port.
            type: int
          profileId:
            description: Pnp Global Settings's profileId.
            type: str
          proxy:
            description: Proxy flag.
            type: bool
        type: dict
      smartAccountId:
        description: Pnp Global Settings's smartAccountId.
        type: str
      syncResult:
        description: Pnp Global Settings's syncResult.
        suboptions:
          syncList:
            description: Pnp Global Settings's syncList.
            elements: dict
            suboptions:
              deviceSnList:
                description: Pnp Global Settings's deviceSnList.
                elements: str
                type: list
              syncType:
                description: Pnp Global Settings's syncType.
                type: str
            type: list
          syncMsg:
            description: Pnp Global Settings's syncMsg.
            type: str
        type: dict
      syncResultStr:
        description: Pnp Global Settings's syncResultStr.
        type: str
      syncStartTime:
        description: Pnp Global Settings's syncStartTime.
        type: int
      syncStatus:
        description: Pnp Global Settings's syncStatus.
        type: str
      tenantId:
        description: Pnp Global Settings's tenantId.
        type: str
      token:
        description: Pnp Global Settings's token.
        type: str
      virtualAccountId:
        description: Pnp Global Settings's virtualAccountId.
        type: str
    type: list
  taskTimeOuts:
    description: Pnp Global Settings's taskTimeOuts.
    suboptions:
      configTimeOut:
        description: Pnp Global Settings's configTimeOut.
        type: int
      generalTimeOut:
        description: Pnp Global Settings's generalTimeOut.
        type: int
      imageDownloadTimeOut:
        description: Pnp Global Settings's imageDownloadTimeOut.
        type: int
    type: dict
  tenantId:
    description: Pnp Global Settings's tenantId.
    type: str
  version:
    description: Pnp Global Settings's version.
    type: int
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Device Onboarding (PnP) UpdatePnPGlobalSettings
  description: Complete reference of the UpdatePnPGlobalSettings API.
  link: https://developer.cisco.com/docs/dna-center/#!update-pn-p-global-settings
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.update_pnp_global_settings,

  - Paths used are
    put /dna/intent/api/v1/onboarding/pnp-settings,

"""

EXAMPLES = r"""
- name: Update all
  cisco.dnac.pnp_global_settings:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    _id: string
    aaaCredentials:
      password: string
      username: string
    acceptEula: true
    defaultProfile:
      cert: string
      fqdnAddresses:
      - string
      ipAddresses:
      - string
      port: 0
      proxy: true
    savaMappingList:
    - autoSyncPeriod: 0
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
    taskTimeOuts:
      configTimeOut: 0
      generalTimeOut: 0
      imageDownloadTimeOut: 0
    tenantId: string
    version: 0

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "savaMappingList": [
        {
          "syncStatus": "string",
          "syncStartTime": 0,
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
          "lastSync": 0,
          "tenantId": "string",
          "profile": {
            "port": 0,
            "addressIpV4": "string",
            "addressFqdn": "string",
            "profileId": "string",
            "proxy": true,
            "makeDefault": true,
            "cert": "string",
            "name": "string"
          },
          "token": "string",
          "expiry": 0,
          "ccoUser": "string",
          "smartAccountId": "string",
          "virtualAccountId": "string",
          "autoSyncPeriod": 0,
          "syncResultStr": "string"
        }
      ],
      "taskTimeOuts": {
        "imageDownloadTimeOut": 0,
        "configTimeOut": 0,
        "generalTimeOut": 0
      },
      "tenantId": "string",
      "aaaCredentials": {
        "password": "string",
        "username": "string"
      },
      "defaultProfile": {
        "fqdnAddresses": [
          "string"
        ],
        "proxy": true,
        "cert": "string",
        "ipAddresses": [
          "string"
        ],
        "port": 0
      },
      "acceptEula": true,
      "id": "string",
      "_id": "string",
      "version": 0
    }
"""
