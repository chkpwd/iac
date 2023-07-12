#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_access_network_condition
short_description: Resource module for Network Access Network Condition
description:
- Manage operations create, update and delete of the resource Network Access Network Condition.
- Network Access - Creates network condition.
- Network Access - Delete network condition.
- Network Access - Update network condition.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  cliDnisList:
    description: <p>This field should contain a Caller ID (CLI), comma, and Called ID
      (DNIS).<br> Line format - Caller ID (CLI), Called ID (DNIS)</p>.
    elements: str
    type: list
  conditionType:
    description: This field determines the content of the conditions field.
    type: str
  description:
    description: Network Access Network Condition's description.
    type: str
  deviceGroupList:
    description: <p>This field should contain a NDG Root, comma, and an NDG
      (that it under the root).<br> Line format - NDG Root Name, NDG, Port</p>.
    elements: str
    type: list
  deviceList:
    description: <p>This field should contain Device-Name,port-number. The device
      name must be the same as the name field in a Network Device object.<br> Line
      format - Device Name,Port</p>.
    elements: str
    type: list
  id:
    description: Network Access Network Condition's id.
    type: str
  ipAddrList:
    description: <p>This field should contain IP-address-or-subnet,port number<br>
      IP address can be IPV4 format (n.n.n.n) or IPV6 format (n n n n n n n n).<br>
      IP subnet can be IPV4 format (n.n.n.n/m) or IPV6 format (n n n n n n n n/m).<br>
      Line format - IP Address or subnet,Port</p>.
    elements: str
    type: list
  link:
    description: Network Access Network Condition's link.
    suboptions:
      href:
        description: Network Access Network Condition's href.
        type: str
      rel:
        description: Network Access Network Condition's rel.
        type: str
      type:
        description: Network Access Network Condition's type.
        type: str
    type: dict
  macAddrList:
    description: <p>This field should contain Endstation MAC address, comma, and
      Destination MAC addresses.<br> Each Max address must include twelve hexadecimal
      digits using formats nn nn nn nn nn nn or nn-nn-nn-nn-nn-nn or nnnn.nnnn.nnnn
      or nnnnnnnnnnnn.<br> Line format - Endstation MAC,Destination MAC </p>.
    elements: str
    type: list
  name:
    description: Network Condition name.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Network Access - Network Conditions
  description: Complete reference of the Network Access - Network Conditions API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!policy-openapi
notes:
  - SDK Method used are
    network_access_network_conditions.NetworkAccessNetworkConditions.create_network_access_network_condition,
    network_access_network_conditions.NetworkAccessNetworkConditions.delete_network_access_network_condition_by_id,
    network_access_network_conditions.NetworkAccessNetworkConditions.update_network_access_network_condition_by_id,

  - Paths used are
    post /network-access/network-condition,
    delete /network-access/network-condition/{id},
    put /network-access/network-condition/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.network_access_network_condition:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    cliDnisList:
    - string
    conditionType: string
    description: string
    deviceGroupList:
    - string
    deviceList:
    - string
    id: string
    ipAddrList:
    - string
    link:
      href: string
      rel: string
      type: string
    macAddrList:
    - string
    name: string

- name: Update by id
  cisco.ise.network_access_network_condition:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    cliDnisList:
    - string
    conditionType: string
    description: string
    deviceGroupList:
    - string
    deviceList:
    - string
    id: string
    ipAddrList:
    - string
    link:
      href: string
      rel: string
      type: string
    macAddrList:
    - string
    name: string

- name: Delete by id
  cisco.ise.network_access_network_condition:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "conditionType": "string",
      "description": "string",
      "id": "string",
      "link": {
        "href": "string",
        "rel": "string",
        "type": "string"
      },
      "name": "string",
      "deviceList": [
        "string"
      ],
      "cliDnisList": [
        "string"
      ],
      "ipAddrList": [
        "string"
      ],
      "macAddrList": [
        "string"
      ],
      "deviceGroupList": [
        "string"
      ]
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "response": {
        "conditionType": "string",
        "description": "string",
        "id": "string",
        "link": {
          "href": "string",
          "rel": "string",
          "type": "string"
        },
        "name": "string",
        "deviceList": [
          "string"
        ],
        "cliDnisList": [
          "string"
        ],
        "ipAddrList": [
          "string"
        ],
        "macAddrList": [
          "string"
        ],
        "deviceGroupList": [
          "string"
        ]
      },
      "version": "string"
    }
"""
