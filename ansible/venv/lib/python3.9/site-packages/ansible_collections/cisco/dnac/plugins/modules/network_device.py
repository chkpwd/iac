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
- Adds the device with given credential.
- Deletes the network device for the given Id.
- Sync the devices provided as input.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  cleanConfig:
    description: CleanConfig query parameter.
    type: bool
    version_added: 4.0.0
  cliTransport:
    description: Network Device's cliTransport.
    type: str
  computeDevice:
    description: ComputeDevice flag.
    type: bool
  enablePassword:
    description: Network Device's enablePassword.
    type: str
  extendedDiscoveryInfo:
    description: Network Device's extendedDiscoveryInfo.
    type: str
  httpPassword:
    description: Network Device's httpPassword.
    type: str
  httpPort:
    description: Network Device's httpPort.
    type: str
  httpSecure:
    description: HttpSecure flag.
    type: bool
  httpUserName:
    description: Network Device's httpUserName.
    type: str
  id:
    description: Id path parameter. Device ID.
    type: str
  ipAddress:
    description: Network Device's ipAddress.
    elements: str
    type: list
  merakiOrgId:
    description: Network Device's merakiOrgId.
    elements: str
    type: list
  netconfPort:
    description: Network Device's netconfPort.
    type: str
  password:
    description: Network Device's password.
    type: str
  serialNumber:
    description: Network Device's serialNumber.
    type: str
  snmpAuthPassphrase:
    description: Network Device's snmpAuthPassphrase.
    type: str
  snmpAuthProtocol:
    description: Network Device's snmpAuthProtocol.
    type: str
  snmpMode:
    description: Network Device's snmpMode.
    type: str
  snmpPrivPassphrase:
    description: Network Device's snmpPrivPassphrase.
    type: str
  snmpPrivProtocol:
    description: Network Device's snmpPrivProtocol.
    type: str
  snmpROCommunity:
    description: Network Device's snmpROCommunity.
    type: str
  snmpRWCommunity:
    description: Network Device's snmpRWCommunity.
    type: str
  snmpRetry:
    description: Network Device's snmpRetry.
    type: int
  snmpTimeout:
    description: Network Device's snmpTimeout.
    type: int
  snmpUserName:
    description: Network Device's snmpUserName.
    type: str
  snmpVersion:
    description: Network Device's snmpVersion.
    type: str
  type:
    description: Network Device's type.
    type: str
  updateMgmtIPaddressList:
    description: Network Device's updateMgmtIPaddressList.
    elements: dict
    suboptions:
      existMgmtIpAddress:
        description: Network Device's existMgmtIpAddress.
        type: str
      newMgmtIpAddress:
        description: Network Device's newMgmtIpAddress.
        type: str
    type: list
  userName:
    description: Network Device's userName.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Devices AddDevice2
  description: Complete reference of the AddDevice2 API.
  link: https://developer.cisco.com/docs/dna-center/#!add-device
- name: Cisco DNA Center documentation for Devices DeleteDeviceById
  description: Complete reference of the DeleteDeviceById API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-device-by-id
- name: Cisco DNA Center documentation for Devices SyncDevices2
  description: Complete reference of the SyncDevices2 API.
  link: https://developer.cisco.com/docs/dna-center/#!sync-devices
notes:
  - SDK Method used are
    devices.Devices.add_device,
    devices.Devices.delete_device_by_id,
    devices.Devices.sync_devices,

  - Paths used are
    post /dna/intent/api/v1/network-device,
    delete /dna/intent/api/v1/network-device/{id},
    put /dna/intent/api/v1/network-device,

  - Removed 'managementIpAddress' options in v4.3.0.
"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.network_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    cliTransport: string
    computeDevice: true
    enablePassword: string
    extendedDiscoveryInfo: string
    httpPassword: string
    httpPort: string
    httpSecure: true
    httpUserName: string
    ipAddress:
    - string
    merakiOrgId:
    - string
    netconfPort: string
    password: string
    serialNumber: string
    snmpAuthPassphrase: string
    snmpAuthProtocol: string
    snmpMode: string
    snmpPrivPassphrase: string
    snmpPrivProtocol: string
    snmpROCommunity: string
    snmpRWCommunity: string
    snmpRetry: 0
    snmpTimeout: 0
    snmpUserName: string
    snmpVersion: string
    type: string
    updateMgmtIPaddressList:
    - existMgmtIpAddress: string
      newMgmtIpAddress: string
    userName: string

- name: Update all
  cisco.dnac.network_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    cliTransport: string
    computeDevice: true
    enablePassword: string
    extendedDiscoveryInfo: string
    httpPassword: string
    httpPort: string
    httpSecure: true
    httpUserName: string
    ipAddress:
    - string
    merakiOrgId:
    - string
    netconfPort: string
    password: string
    serialNumber: string
    snmpAuthPassphrase: string
    snmpAuthProtocol: string
    snmpMode: string
    snmpPrivPassphrase: string
    snmpPrivProtocol: string
    snmpROCommunity: string
    snmpRWCommunity: string
    snmpRetry: 0
    snmpTimeout: 0
    snmpUserName: string
    snmpVersion: string
    type: string
    updateMgmtIPaddressList:
    - existMgmtIpAddress: string
      newMgmtIpAddress: string
    userName: string

- name: Delete by id
  cisco.dnac.network_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    cleanConfig: true
    id: string

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
