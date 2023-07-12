#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device
short_description: Resource module for Network Device
description:
- Manage operations create, update and delete of the resource Network Device.
- This API creates a network device.
- This API deletes a network device by ID.
- This API deletes a network device by name.
- This API allows the client to update a network device by ID.
- This API allows the client to update a network device by name.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  NetworkDeviceGroupList:
    description: List of Network Device Group names for this node.
    elements: str
    type: list
  NetworkDeviceIPList:
    description: List of IP Subnets for this node.
    elements: dict
    suboptions:
      getIpaddressExclude:
        description: It can be either single IP address or IP range address.
        type: str
      ipaddress:
        description: Network Device's ipaddress.
        type: str
      mask:
        description: Network Device's mask.
        type: int
    type: list
  authenticationSettings:
    description: Network Device's authenticationSettings.
    suboptions:
      dtlsRequired:
        description: This value enforces use of dtls.
        type: bool
      enableKeyWrap:
        description: EnableKeyWrap flag.
        type: bool
      enableMultiSecret:
        description: Network Device's enableMultiSecret.
        type: str
      enabled:
        description: Enabled flag.
        type: bool
      keyEncryptionKey:
        description: Network Device's keyEncryptionKey.
        type: str
      keyInputFormat:
        description: Allowed values - ASCII, - HEXADECIMAL.
        type: str
      messageAuthenticatorCodeKey:
        description: Network Device's messageAuthenticatorCodeKey.
        type: str
      networkProtocol:
        description: Allowed values - RADIUS, - TACACS_PLUS.
        type: str
      radiusSharedSecret:
        description: Network Device's radiusSharedSecret.
        type: str
      secondRADIUSSharedSecret:
        description: Network Device's secondRADIUSSharedSecret.
        type: str
    type: dict
  coaPort:
    description: Network Device's coaPort.
    type: int
  description:
    description: Network Device's description.
    type: str
  dtlsDnsName:
    description: This value is used to verify the client identity contained in the X.509
      RADIUS/DTLS client certificate.
    type: str
  id:
    description: Network Device's id.
    type: str
  modelName:
    description: Network Device's modelName.
    type: str
  name:
    description: Network Device's name.
    type: str
  profileName:
    description: Network Device's profileName.
    type: str
  snmpsettings:
    description: Network Device's snmpsettings.
    suboptions:
      linkTrapQuery:
        description: LinkTrapQuery flag.
        type: bool
      macTrapQuery:
        description: MacTrapQuery flag.
        type: bool
      originatingPolicyServicesNode:
        description: Network Device's originatingPolicyServicesNode.
        type: str
      pollingInterval:
        description: Network Device's pollingInterval.
        type: int
      roCommunity:
        description: Network Device's roCommunity.
        type: str
      version:
        description: Network Device's version.
        type: str
    type: dict
  softwareVersion:
    description: Network Device's softwareVersion.
    type: str
  tacacsSettings:
    description: Network Device's tacacsSettings.
    suboptions:
      connectModeOptions:
        description: Allowed values - OFF, - ON_LEGACY, - ON_DRAFT_COMPLIANT.
        type: str
      sharedSecret:
        description: Network Device's sharedSecret.
        type: str
    type: dict
  trustsecsettings:
    description: Network Device's trustsecsettings.
    suboptions:
      deviceAuthenticationSettings:
        description: Network Device's deviceAuthenticationSettings.
        suboptions:
          sgaDeviceId:
            description: Network Device's sgaDeviceId.
            type: str
          sgaDevicePassword:
            description: Network Device's sgaDevicePassword.
            type: str
        type: dict
      deviceConfigurationDeployment:
        description: Network Device's deviceConfigurationDeployment.
        suboptions:
          enableModePassword:
            description: Network Device's enableModePassword.
            type: str
          execModePassword:
            description: Network Device's execModePassword.
            type: str
          execModeUsername:
            description: Network Device's execModeUsername.
            type: str
          includeWhenDeployingSGTUpdates:
            description: IncludeWhenDeployingSGTUpdates flag.
            type: bool
        type: dict
      pushIdSupport:
        description: PushIdSupport flag.
        type: bool
      sgaNotificationAndUpdates:
        description: Network Device's sgaNotificationAndUpdates.
        suboptions:
          coaSourceHost:
            description: Network Device's coaSourceHost.
            type: str
          downlaodEnvironmentDataEveryXSeconds:
            description: Network Device's downlaodEnvironmentDataEveryXSeconds.
            type: int
          downlaodPeerAuthorizationPolicyEveryXSeconds:
            description: Network Device's downlaodPeerAuthorizationPolicyEveryXSeconds.
            type: int
          downloadSGACLListsEveryXSeconds:
            description: Network Device's downloadSGACLListsEveryXSeconds.
            type: int
          otherSGADevicesToTrustThisDevice:
            description: OtherSGADevicesToTrustThisDevice flag.
            type: bool
          reAuthenticationEveryXSeconds:
            description: Network Device's reAuthenticationEveryXSeconds.
            type: int
          sendConfigurationToDevice:
            description: SendConfigurationToDevice flag.
            type: bool
          sendConfigurationToDeviceUsing:
            description: Allowed values - ENABLE_USING_COA, - ENABLE_USING_CLI, - DISABLE_ALL.
            type: str
        type: dict
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    network_device.NetworkDevice.create_network_device,
    network_device.NetworkDevice.delete_network_device_by_id,
    network_device.NetworkDevice.delete_network_device_by_name,
    network_device.NetworkDevice.update_network_device_by_id,
    network_device.NetworkDevice.update_network_device_by_name,

  - Paths used are
    post /ers/config/networkdevice,
    delete /ers/config/networkdevice/name/{name},
    delete /ers/config/networkdevice/{id},
    put /ers/config/networkdevice/name/{name},
    put /ers/config/networkdevice/{id},

"""

EXAMPLES = r"""
- name: Update by name
  cisco.ise.network_device:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    NetworkDeviceGroupList:
    - string
    NetworkDeviceIPList:
    - getIpaddressExclude: string
      ipaddress: string
      mask: 0
    authenticationSettings:
      dtlsRequired: true
      enableKeyWrap: true
      enableMultiSecret: string
      enabled: true
      keyEncryptionKey: string
      keyInputFormat: string
      messageAuthenticatorCodeKey: string
      networkProtocol: string
      radiusSharedSecret: string
      secondRadiusSharedSecret: string
    coaPort: 0
    description: string
    dtlsDnsName: string
    id: string
    modelName: string
    name: string
    profileName: string
    snmpsettings:
      linkTrapQuery: true
      macTrapQuery: true
      originatingPolicyServicesNode: string
      pollingInterval: 0
      roCommunity: string
      version: string
    softwareVersion: string
    tacacsSettings:
      connectModeOptions: string
      sharedSecret: string
    trustsecsettings:
      deviceAuthenticationSettings:
        sgaDeviceId: string
        sgaDevicePassword: string
      deviceConfigurationDeployment:
        enableModePassword: string
        execModePassword: string
        execModeUsername: string
        includeWhenDeployingSGTUpdates: true
      pushIdSupport: true
      sgaNotificationAndUpdates:
        coaSourceHost: string
        downlaodEnvironmentDataEveryXSeconds: 0
        downlaodPeerAuthorizationPolicyEveryXSeconds: 0
        downloadSGACLListsEveryXSeconds: 0
        otherSGADevicesToTrustThisDevice: true
        reAuthenticationEveryXSeconds: 0
        sendConfigurationToDevice: true
        sendConfigurationToDeviceUsing: string

- name: Delete by name
  cisco.ise.network_device:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    name: string

- name: Update by id
  cisco.ise.network_device:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    NetworkDeviceGroupList:
    - string
    NetworkDeviceIPList:
    - getIpaddressExclude: string
      ipaddress: string
      mask: 0
    authenticationSettings:
      dtlsRequired: true
      enableKeyWrap: true
      enableMultiSecret: string
      enabled: true
      keyEncryptionKey: string
      keyInputFormat: string
      messageAuthenticatorCodeKey: string
      networkProtocol: string
      radiusSharedSecret: string
      secondRadiusSharedSecret: string
    coaPort: 0
    description: string
    dtlsDnsName: string
    id: string
    modelName: string
    name: string
    profileName: string
    snmpsettings:
      linkTrapQuery: true
      macTrapQuery: true
      originatingPolicyServicesNode: string
      pollingInterval: 0
      roCommunity: string
      version: string
    softwareVersion: string
    tacacsSettings:
      connectModeOptions: string
      sharedSecret: string
    trustsecsettings:
      deviceAuthenticationSettings:
        sgaDeviceId: string
        sgaDevicePassword: string
      deviceConfigurationDeployment:
        enableModePassword: string
        execModePassword: string
        execModeUsername: string
        includeWhenDeployingSGTUpdates: true
      pushIdSupport: true
      sgaNotificationAndUpdates:
        coaSourceHost: string
        downlaodEnvironmentDataEveryXSeconds: 0
        downlaodPeerAuthorizationPolicyEveryXSeconds: 0
        downloadSGACLListsEveryXSeconds: 0
        otherSGADevicesToTrustThisDevice: true
        reAuthenticationEveryXSeconds: 0
        sendConfigurationToDevice: true
        sendConfigurationToDeviceUsing: string

- name: Delete by id
  cisco.ise.network_device:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.network_device:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    NetworkDeviceGroupList:
    - string
    NetworkDeviceIPList:
    - getIpaddressExclude: string
      ipaddress: string
      mask: 0
    authenticationSettings:
      dtlsRequired: true
      enableKeyWrap: true
      enableMultiSecret: string
      enabled: true
      keyEncryptionKey: string
      keyInputFormat: string
      messageAuthenticatorCodeKey: string
      networkProtocol: string
      radiusSharedSecret: string
      secondRadiusSharedSecret: string
    coaPort: 0
    description: string
    dtlsDnsName: string
    modelName: string
    name: string
    profileName: string
    snmpsettings:
      linkTrapQuery: true
      macTrapQuery: true
      originatingPolicyServicesNode: string
      pollingInterval: 0
      roCommunity: string
      version: string
    softwareVersion: string
    tacacsSettings:
      connectModeOptions: string
      sharedSecret: string
    trustsecsettings:
      deviceAuthenticationSettings:
        sgaDeviceId: string
        sgaDevicePassword: string
      deviceConfigurationDeployment:
        enableModePassword: string
        execModePassword: string
        execModeUsername: string
        includeWhenDeployingSGTUpdates: true
      pushIdSupport: true
      sgaNotificationAndUpdates:
        coaSourceHost: string
        downlaodEnvironmentDataEveryXSeconds: 0
        downlaodPeerAuthorizationPolicyEveryXSeconds: 0
        downloadSGACLListsEveryXSeconds: 0
        otherSGADevicesToTrustThisDevice: true
        reAuthenticationEveryXSeconds: 0
        sendConfigurationToDevice: true
        sendConfigurationToDeviceUsing: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "authenticationSettings": {
        "networkProtocol": "string",
        "secondRadiusSharedSecret": "string",
        "radiusSharedSecret": "string",
        "enableKeyWrap": true,
        "enabled": true,
        "dtlsRequired": true,
        "enableMultiSecret": "string",
        "keyEncryptionKey": "string",
        "messageAuthenticatorCodeKey": "string",
        "keyInputFormat": "string"
      },
      "snmpsettings": {
        "version": "string",
        "roCommunity": "string",
        "pollingInterval": 0,
        "linkTrapQuery": true,
        "macTrapQuery": true,
        "originatingPolicyServicesNode": "string"
      },
      "trustsecsettings": {
        "deviceAuthenticationSettings": {
          "sgaDeviceId": "string",
          "sgaDevicePassword": "string"
        },
        "sgaNotificationAndUpdates": {
          "downlaodEnvironmentDataEveryXSeconds": 0,
          "downlaodPeerAuthorizationPolicyEveryXSeconds": 0,
          "reAuthenticationEveryXSeconds": 0,
          "downloadSGACLListsEveryXSeconds": 0,
          "otherSGADevicesToTrustThisDevice": true,
          "sendConfigurationToDevice": true,
          "sendConfigurationToDeviceUsing": "string",
          "coaSourceHost": "string"
        },
        "deviceConfigurationDeployment": {
          "includeWhenDeployingSGTUpdates": true,
          "enableModePassword": "string",
          "execModePassword": "string",
          "execModeUsername": "string"
        },
        "pushIdSupport": true
      },
      "tacacsSettings": {
        "sharedSecret": "string",
        "connectModeOptions": "string"
      },
      "profileName": "string",
      "coaPort": 0,
      "dtlsDnsName": "string",
      "modelName": "string",
      "softwareVersion": "string",
      "NetworkDeviceIPList": [
        {
          "ipaddress": "string",
          "mask": 0,
          "getIpaddressExclude": "string"
        }
      ],
      "NetworkDeviceGroupList": [
        "string"
      ],
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "UpdatedFieldsList": {
        "updatedField": [
          {
            "field": "string",
            "oldValue": "string",
            "newValue": "string"
          }
        ],
        "field": "string",
        "oldValue": "string",
        "newValue": "string"
      }
    }
"""
