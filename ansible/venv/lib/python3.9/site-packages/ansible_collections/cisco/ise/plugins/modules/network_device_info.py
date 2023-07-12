#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_info
short_description: Information module for Network Device
description:
- Get all Network Device.
- Get Network Device by id.
- Get Network Device by name.
- This API allows the client to get a network device by ID.
- This API allows the client to get a network device by name.
- This API allows the client to get all the network devices.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  name:
    description:
    - Name path parameter.
    type: str
  id:
    description:
    - Id path parameter.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
  sortasc:
    description:
    - Sortasc query parameter. Sort asc.
    type: str
  sortdsc:
    description:
    - Sortdsc query parameter. Sort desc.
    type: str
  filter:
    description:
    - >
      Filter query parameter. **Simple filtering** should be available through the filter query string parameter.
      The structure of a filter is a triplet of field operator and value separated with dots. More than one filter
      can be sent. The logical operator common to ALL filter criteria will be by default AND, and can be changed
      by using the "filterType=or" query string parameter.
    - Each resource Data model description should specify if an attribute is a filtered field.
    - The 'EQ' operator describes 'Equals'.
    - The 'NEQ' operator describes 'Not Equals'.
    - The 'GT' operator describes 'Greater Than'.
    - The 'LT' operator describes 'Less Than'.
    - The 'STARTSW' operator describes 'Starts With'.
    - The 'NSTARTSW' operator describes 'Not Starts With'.
    - The 'ENDSW' operator describes 'Ends With'.
    - The 'NENDSW' operator describes 'Not Ends With'.
    - The 'CONTAINS' operator describes 'Contains'.
    - The 'NCONTAINS' operator describes 'Not Contains'.
    elements: str
    type: list
  filterType:
    description:
    - >
      FilterType query parameter. The logical operator common to ALL filter criteria will be by default AND, and
      can be changed by using the parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    network_device.NetworkDevice.get_network_device_by_id,
    network_device.NetworkDevice.get_network_device_by_name,
    network_device.NetworkDevice.get_network_device_generator,

  - Paths used are
    get /ers/config/networkdevice,
    get /ers/config/networkdevice/name/{name},
    get /ers/config/networkdevice/{id},

"""

EXAMPLES = r"""
- name: Get all Network Device
  cisco.ise.network_device_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
    sortasc: string
    sortdsc: string
    filter: []
    filterType: AND
  register: result

- name: Get Network Device by id
  cisco.ise.network_device_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Network Device by name
  cisco.ise.network_device_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
  register: result

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

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
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
    ]
"""
