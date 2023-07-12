#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: discovery
short_description: Resource module for Discovery
description:
- Manage operations create, update and delete of the resource Discovery.
- Initiates discovery with the given parameters.
- Stops all the discoveries and removes them.
- >
   Stops the discovery for the given Discovery ID and removes it. Discovery ID can be obtained using the "Get
   Discoveries by range" API.
- Stops or starts an existing discovery.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  attributeInfo:
    description: Discovery's attributeInfo.
    type: dict
  cdpLevel:
    description: Discovery's cdpLevel.
    type: int
  deviceIds:
    description: Discovery's deviceIds.
    type: str
  discoveryCondition:
    description: Discovery's discoveryCondition.
    type: str
  discoveryStatus:
    description: Discovery's discoveryStatus.
    type: str
  discoveryType:
    description: Discovery's discoveryType.
    type: str
  enablePasswordList:
    description: Discovery's enablePasswordList.
    type: str
  globalCredentialIdList:
    description: Discovery's globalCredentialIdList.
    elements: str
    type: list
  httpReadCredential:
    description: Discovery's httpReadCredential.
    suboptions:
      comments:
        description: Discovery's comments.
        type: str
      credentialType:
        description: Discovery's credentialType.
        type: str
      description:
        description: Discovery's description.
        type: str
      id:
        description: Discovery's id.
        type: str
      instanceTenantId:
        description: Discovery's instanceTenantId.
        type: str
      instanceUuid:
        description: Discovery's instanceUuid.
        type: str
      password:
        description: Discovery's password.
        type: str
      port:
        description: Discovery's port.
        type: int
      secure:
        description: Secure flag.
        type: bool
      username:
        description: Discovery's username.
        type: str
    type: dict
  httpWriteCredential:
    description: Discovery's httpWriteCredential.
    suboptions:
      comments:
        description: Discovery's comments.
        type: str
      credentialType:
        description: Discovery's credentialType.
        type: str
      description:
        description: Discovery's description.
        type: str
      id:
        description: Discovery's id.
        type: str
      instanceTenantId:
        description: Discovery's instanceTenantId.
        type: str
      instanceUuid:
        description: Discovery's instanceUuid.
        type: str
      password:
        description: Discovery's password.
        type: str
      port:
        description: Discovery's port.
        type: int
      secure:
        description: Secure flag.
        type: bool
      username:
        description: Discovery's username.
        type: str
    type: dict
  id:
    description: Discovery's id.
    type: str
  ipAddressList:
    description: Discovery's ipAddressList.
    type: str
  ipFilterList:
    description: Discovery's ipFilterList.
    type: str
  isAutoCdp:
    description: IsAutoCdp flag.
    type: bool
  lldpLevel:
    description: Discovery's lldpLevel.
    type: int
  name:
    description: Discovery's name.
    type: str
  netconfPort:
    description: Discovery's netconfPort.
    type: str
  numDevices:
    description: Discovery's numDevices.
    type: int
  parentDiscoveryId:
    description: Discovery's parentDiscoveryId.
    type: str
  passwordList:
    description: Discovery's passwordList.
    type: str
  preferredMgmtIPMethod:
    description: Discovery's preferredMgmtIPMethod.
    type: str
  protocolOrder:
    description: Discovery's protocolOrder.
    type: str
  retry:
    description: Number of times to try establishing connection to device.
    type: int
  retryCount:
    description: Discovery's retryCount.
    type: int
  snmpAuthPassphrase:
    description: Discovery's snmpAuthPassphrase.
    type: str
  snmpAuthProtocol:
    description: Discovery's snmpAuthProtocol.
    type: str
  snmpMode:
    description: Discovery's snmpMode.
    type: str
  snmpPrivPassphrase:
    description: Discovery's snmpPrivPassphrase.
    type: str
  snmpPrivProtocol:
    description: Discovery's snmpPrivProtocol.
    type: str
  snmpROCommunity:
    description: Snmp RO community of the devices to be discovered.
    type: str
  snmpROCommunityDesc:
    description: Description for Snmp RO community.
    type: str
  snmpRWCommunity:
    description: Snmp RW community of the devices to be discovered.
    type: str
  snmpRWCommunityDesc:
    description: Description for Snmp RW community.
    type: str
  snmpRoCommunity:
    description: Discovery's snmpRoCommunity.
    type: str
  snmpRoCommunityDesc:
    description: Discovery's snmpRoCommunityDesc.
    type: str
  snmpRwCommunity:
    description: Discovery's snmpRwCommunity.
    type: str
  snmpRwCommunityDesc:
    description: Discovery's snmpRwCommunityDesc.
    type: str
  snmpUserName:
    description: Discovery's snmpUserName.
    type: str
  snmpVersion:
    description: Version of SNMP. V2 or v3.
    type: str
  timeOut:
    description: Discovery's timeOut.
    type: int
  timeout:
    description: Time to wait for device response in seconds.
    type: int
  updateMgmtIp:
    description: UpdateMgmtIp flag.
    type: bool
  userNameList:
    description: Discovery's userNameList.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Discovery StartDiscovery
  description: Complete reference of the StartDiscovery API.
  link: https://developer.cisco.com/docs/dna-center/#!start-discovery
- name: Cisco DNA Center documentation for Discovery DeleteAllDiscovery
  description: Complete reference of the DeleteAllDiscovery API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-all-discovery
- name: Cisco DNA Center documentation for Discovery DeleteDiscoveryById
  description: Complete reference of the DeleteDiscoveryById API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-discovery-by-id
- name: Cisco DNA Center documentation for Discovery UpdatesAnExistingDiscoveryBySpecifiedId
  description: Complete reference of the UpdatesAnExistingDiscoveryBySpecifiedId API.
  link: https://developer.cisco.com/docs/dna-center/#!updates-an-existing-discovery-by-specified-id
notes:
  - SDK Method used are
    discovery.Discovery.delete_discovery_by_id,
    discovery.Discovery.start_discovery,
    discovery.Discovery.updates_discovery_by_id,

  - Paths used are
    post /dna/intent/api/v1/discovery,
    delete /dna/intent/api/v1/discovery,
    delete /dna/intent/api/v1/discovery/{id},
    put /dna/intent/api/v1/discovery,

"""

EXAMPLES = r"""
- name: Delete all
  cisco.dnac.discovery:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent

- name: Update all
  cisco.dnac.discovery:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    attributeInfo: {}
    cdpLevel: 0
    deviceIds: string
    discoveryCondition: string
    discoveryStatus: string
    discoveryType: string
    enablePasswordList: string
    globalCredentialIdList:
    - string
    httpReadCredential:
      comments: string
      credentialType: string
      description: string
      id: string
      instanceTenantId: string
      instanceUuid: string
      password: string
      port: 0
      secure: true
      username: string
    httpWriteCredential:
      comments: string
      credentialType: string
      description: string
      id: string
      instanceTenantId: string
      instanceUuid: string
      password: string
      port: 0
      secure: true
      username: string
    id: string
    ipAddressList: string
    ipFilterList: string
    isAutoCdp: true
    lldpLevel: 0
    name: string
    netconfPort: string
    numDevices: 0
    parentDiscoveryId: string
    passwordList: string
    preferredMgmtIPMethod: string
    protocolOrder: string
    retryCount: 0
    snmpAuthPassphrase: string
    snmpAuthProtocol: string
    snmpMode: string
    snmpPrivPassphrase: string
    snmpPrivProtocol: string
    snmpRoCommunity: string
    snmpRoCommunityDesc: string
    snmpRwCommunity: string
    snmpRwCommunityDesc: string
    snmpUserName: string
    timeOut: 0
    updateMgmtIp: true
    userNameList: string

- name: Create
  cisco.dnac.discovery:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    cdpLevel: 0
    discoveryType: string
    enablePasswordList:
    - string
    globalCredentialIdList:
    - string
    httpReadCredential:
      password: string
      port: 0
      secure: true
      username: string
    httpWriteCredential:
      password: string
      port: 0
      secure: true
      username: string
    ipAddressList: string
    ipFilterList:
    - string
    lldpLevel: 0
    name: string
    netconfPort: string
    passwordList:
    - string
    preferredMgmtIPMethod: string
    protocolOrder: string
    retry: 0
    snmpAuthPassphrase: string
    snmpAuthProtocol: string
    snmpMode: string
    snmpPrivPassphrase: string
    snmpPrivProtocol: string
    snmpROCommunity: string
    snmpROCommunityDesc: string
    snmpRWCommunity: string
    snmpRWCommunityDesc: string
    snmpUserName: string
    snmpVersion: string
    timeout: 0
    userNameList:
    - string

- name: Delete by id
  cisco.dnac.discovery:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
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
