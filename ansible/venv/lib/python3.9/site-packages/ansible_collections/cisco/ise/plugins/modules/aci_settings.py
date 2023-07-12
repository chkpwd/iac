#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: aci_settings
short_description: Resource module for ACI Settings
description:
- Manage operation update of the resource ACI Settings.
- This API allows the client to update ACI settings.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  aci50:
    description: Enable 5.0 ACI Version.
    type: bool
  aci51:
    description: Enable 5.1 ACI Version.
    type: bool
  aciipaddress:
    description: ACI Domain manager Ip Address.
    type: str
  acipassword:
    description: ACI Domain manager Password.
    type: str
  aciuserName:
    description: ACI Domain manager Username.
    type: str
  adminName:
    description: ACI Cluster Admin name.
    type: str
  adminPassword:
    description: ACI Cluster Admin password.
    type: str
  allSXPDomain:
    description: AllSXPDomain flag.
    type: bool
  defaultSGtName:
    description: ACI Settings's defaultSGtName.
    type: str
  enableACI:
    description: Enable ACI Integration.
    type: bool
  enableDataPlane:
    description: EnableDataPlane flag.
    type: bool
  enableElementsLimit:
    description: EnableElementsLimit flag.
    type: bool
  id:
    description: Resource UUID value.
    type: str
  ipAddressHostName:
    description: ACI Cluster IP Address / Host name.
    type: str
  l3RouteNetwork:
    description: ACI Settings's l3RouteNetwork.
    type: str
  maxNumIepgFromACI:
    description: ACI Settings's maxNumIepgFromACI.
    type: int
  maxNumSGtToACI:
    description: ACI Settings's maxNumSGtToACI.
    type: int
  specificSXPDomain:
    description: SpecificSXPDomain flag.
    type: bool
  specifixSXPDomainList:
    description: ACI Settings's specifixSXPDomainList.
    elements: str
    type: list
  suffixToEpg:
    description: ACI Settings's suffixToEpg.
    type: str
  suffixToSGt:
    description: ACI Settings's suffixToSGt.
    type: str
  tenantName:
    description: ACI Settings's tenantName.
    type: str
  untaggedPacketIepgName:
    description: ACI Settings's untaggedPacketIepgName.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    aci_settings.AciSettings.update_aci_settings_by_id,

  - Paths used are
    put /ers/config/acisettings/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.aci_settings:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    aci50: true
    aci51: true
    aciipaddress: string
    acipassword: string
    aciuserName: string
    adminName: string
    adminPassword: string
    allSxpDomain: true
    defaultSgtName: string
    enableAci: true
    enableDataPlane: true
    enableElementsLimit: true
    id: string
    ipAddressHostName: string
    l3RouteNetwork: string
    maxNumIepgFromAci: 0
    maxNumSgtToAci: 0
    specificSxpDomain: true
    specifixSxpDomainList:
    - string
    suffixToEpg: string
    suffixToSgt: string
    tenantName: string
    untaggedPacketIepgName: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "enableAci": true,
      "ipAddressHostName": "string",
      "adminName": "string",
      "adminPassword": "string",
      "aciipaddress": "string",
      "aciuserName": "string",
      "acipassword": "string",
      "tenantName": "string",
      "l3RouteNetwork": "string",
      "suffixToEpg": "string",
      "suffixToSgt": "string",
      "allSxpDomain": true,
      "specificSxpDomain": true,
      "specifixSxpDomainList": [
        "string"
      ],
      "enableDataPlane": true,
      "untaggedPacketIepgName": "string",
      "defaultSgtName": "string",
      "enableElementsLimit": true,
      "maxNumIepgFromAci": 0,
      "maxNumSgtToAci": 0,
      "aci50": true,
      "aci51": true
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
