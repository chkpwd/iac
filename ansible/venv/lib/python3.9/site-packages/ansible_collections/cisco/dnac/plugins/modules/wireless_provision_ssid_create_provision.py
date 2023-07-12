#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_provision_ssid_create_provision
short_description: Resource module for Wireless Provision Ssid Create Provision
description:
- Manage operation create of the resource Wireless Provision Ssid Create Provision.
- >
   Creates SSID, updates the SSID to the corresponding site profiles and provision it to the devices matching the
   given sites.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  enableFabric:
    description: Enable SSID for Fabric.
    type: bool
  flexConnect:
    description: Wireless Provision Ssid Create Provision's flexConnect.
    suboptions:
      enableFlexConnect:
        description: Enable Flex Connect.
        type: bool
      localToVlan:
        description: Local To Vlan (range is 1 to 4094).
        type: int
    type: dict
  headers:
    description: Additional headers.
    type: dict
  managedAPLocations:
    description: Managed AP Locations (Enter entire Site(s) hierarchy).
    elements: str
    type: list
  ssidDetails:
    description: Wireless Provision Ssid Create Provision's ssidDetails.
    suboptions:
      enableBroadcastSSID:
        description: Enable Broadcast SSID.
        type: bool
      enableFastLane:
        description: Enable Fast Lane.
        type: bool
      enableMACFiltering:
        description: Enable MAC Filtering.
        type: bool
      fastTransition:
        description: Fast Transition.
        type: str
      name:
        description: SSID Name.
        type: str
      passphrase:
        description: Pass Phrase ( Only applicable for SSID with PERSONAL auth type
          ).
        type: str
      radioPolicy:
        description: Radio Policy.
        type: str
      securityLevel:
        description: Security Level(For guest SSID OPEN/WEB_AUTH, For Enterprise SSID
          ENTERPRISE/PERSONAL/OPEN).
        type: str
      trafficType:
        description: Traffic Type.
        type: str
      webAuthURL:
        description: Web Auth URL.
        type: str
    type: dict
  ssidType:
    description: SSID Type.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Wireless CreateAndProvisionSSID
  description: Complete reference of the CreateAndProvisionSSID API.
  link: https://developer.cisco.com/docs/dna-center/#!create-and-provision-ssid
notes:
  - SDK Method used are
    wireless.Wireless.create_and_provision_ssid,

  - Paths used are
    post /dna/intent/api/v1/business/ssid,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.wireless_provision_ssid_create_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    enableFabric: true
    flexConnect:
      enableFlexConnect: true
      localToVlan: 0
    headers: '{{my_headers | from_json}}'
    managedAPLocations:
    - string
    ssidDetails:
      enableBroadcastSSID: true
      enableFastLane: true
      enableMACFiltering: true
      fastTransition: string
      name: string
      passphrase: string
      radioPolicy: string
      securityLevel: string
      trafficType: string
      webAuthURL: string
    ssidType: string

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
