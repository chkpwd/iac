#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device
short_description: Resource module for Pnp Device
description:
- Manage operations create, update and delete of the resource Pnp Device.
- Adds a device to the PnP database.
- Deletes specified device from PnP database.
- Updates device details specified by device id in PnP database.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  _id:
    description: Pnp Device's _id.
    type: str
  deviceInfo:
    description: Pnp Device's deviceInfo.
    suboptions:
      aaaCredentials:
        description: Pnp Device's aaaCredentials.
        suboptions:
          password:
            description: Pnp Device's password.
            type: str
          username:
            description: Pnp Device's username.
            type: str
        type: dict
      addedOn:
        description: Pnp Device's addedOn.
        type: int
      addnMacAddrs:
        description: Pnp Device's addnMacAddrs.
        elements: str
        type: list
      agentType:
        description: Pnp Device's agentType.
        type: str
      authStatus:
        description: Pnp Device's authStatus.
        type: str
      authenticatedSudiSerialNo:
        description: Pnp Device's authenticatedSudiSerialNo.
        type: str
      capabilitiesSupported:
        description: Pnp Device's capabilitiesSupported.
        elements: str
        type: list
      cmState:
        description: Pnp Device's cmState.
        type: str
      description:
        description: Pnp Device's description.
        type: str
      deviceSudiSerialNos:
        description: Pnp Device's deviceSudiSerialNos.
        elements: str
        type: list
      deviceType:
        description: Pnp Device's deviceType.
        type: str
      featuresSupported:
        description: Pnp Device's featuresSupported.
        elements: str
        type: list
      fileSystemList:
        description: Pnp Device's fileSystemList.
        elements: dict
        suboptions:
          freespace:
            description: Pnp Device's freespace.
            type: int
          name:
            description: Pnp Device's name.
            type: str
          readable:
            description: Readable flag.
            type: bool
          size:
            description: Pnp Device's size.
            type: int
          type:
            description: Pnp Device's type.
            type: str
          writeable:
            description: Writeable flag.
            type: bool
        type: list
      firstContact:
        description: Pnp Device's firstContact.
        type: int
      hostname:
        description: Pnp Device's hostname.
        type: str
      httpHeaders:
        description: Pnp Device's httpHeaders.
        elements: dict
        suboptions:
          key:
            description: Pnp Device's key.
            type: str
          value:
            description: Pnp Device's value.
            type: str
        type: list
      imageFile:
        description: Pnp Device's imageFile.
        type: str
      imageVersion:
        description: Pnp Device's imageVersion.
        type: str
      ipInterfaces:
        description: Pnp Device's ipInterfaces.
        elements: dict
        suboptions:
          ipv4Address:
            description: Pnp Device's ipv4Address.
            type: dict
          ipv6AddressList:
            description: Pnp Device's ipv6AddressList.
            elements: dict
            type: list
          macAddress:
            description: Pnp Device's macAddress.
            type: str
          name:
            description: Pnp Device's name.
            type: str
          status:
            description: Pnp Device's status.
            type: str
        type: list
      lastContact:
        description: Pnp Device's lastContact.
        type: int
      lastSyncTime:
        description: Pnp Device's lastSyncTime.
        type: int
      lastUpdateOn:
        description: Pnp Device's lastUpdateOn.
        type: int
      location:
        description: Pnp Device's location.
        suboptions:
          address:
            description: Pnp Device's address.
            type: str
          altitude:
            description: Pnp Device's altitude.
            type: str
          latitude:
            description: Pnp Device's latitude.
            type: str
          longitude:
            description: Pnp Device's longitude.
            type: str
          siteId:
            description: Pnp Device's siteId.
            type: str
        type: dict
      macAddress:
        description: Pnp Device's macAddress.
        type: str
      mode:
        description: Pnp Device's mode.
        type: str
      name:
        description: Pnp Device's name.
        type: str
      neighborLinks:
        description: Pnp Device's neighborLinks.
        elements: dict
        suboptions:
          localInterfaceName:
            description: Pnp Device's localInterfaceName.
            type: str
          localMacAddress:
            description: Pnp Device's localMacAddress.
            type: str
          localShortInterfaceName:
            description: Pnp Device's localShortInterfaceName.
            type: str
          remoteDeviceName:
            description: Pnp Device's remoteDeviceName.
            type: str
          remoteInterfaceName:
            description: Pnp Device's remoteInterfaceName.
            type: str
          remoteMacAddress:
            description: Pnp Device's remoteMacAddress.
            type: str
          remotePlatform:
            description: Pnp Device's remotePlatform.
            type: str
          remoteShortInterfaceName:
            description: Pnp Device's remoteShortInterfaceName.
            type: str
          remoteVersion:
            description: Pnp Device's remoteVersion.
            type: str
        type: list
      onbState:
        description: Pnp Device's onbState.
        type: str
      pid:
        description: Pnp Device's pid.
        type: str
      pnpProfileList:
        description: Pnp Device's pnpProfileList.
        elements: dict
        suboptions:
          createdBy:
            description: Pnp Device's createdBy.
            type: str
          discoveryCreated:
            description: DiscoveryCreated flag.
            type: bool
          primaryEndpoint:
            description: Pnp Device's primaryEndpoint.
            suboptions:
              certificate:
                description: Pnp Device's certificate.
                type: str
              fqdn:
                description: Pnp Device's fqdn.
                type: str
              ipv4Address:
                description: Pnp Device's ipv4Address.
                type: dict
              ipv6Address:
                description: Pnp Device's ipv6Address.
                type: dict
              port:
                description: Pnp Device's port.
                type: int
              protocol:
                description: Pnp Device's protocol.
                type: str
            type: dict
          profileName:
            description: Pnp Device's profileName.
            type: str
          secondaryEndpoint:
            description: Pnp Device's secondaryEndpoint.
            suboptions:
              certificate:
                description: Pnp Device's certificate.
                type: str
              fqdn:
                description: Pnp Device's fqdn.
                type: str
              ipv4Address:
                description: Pnp Device's ipv4Address.
                type: dict
              ipv6Address:
                description: Pnp Device's ipv6Address.
                type: dict
              port:
                description: Pnp Device's port.
                type: int
              protocol:
                description: Pnp Device's protocol.
                type: str
            type: dict
        type: list
      populateInventory:
        description: PopulateInventory flag.
        type: bool
      preWorkflowCliOuputs:
        description: Pnp Device's preWorkflowCliOuputs.
        elements: dict
        suboptions:
          cli:
            description: Pnp Device's cli.
            type: str
          cliOutput:
            description: Pnp Device's cliOutput.
            type: str
        type: list
      projectId:
        description: Pnp Device's projectId.
        type: str
      projectName:
        description: Pnp Device's projectName.
        type: str
      reloadRequested:
        description: ReloadRequested flag.
        type: bool
      serialNumber:
        description: Pnp Device's serialNumber.
        type: str
      smartAccountId:
        description: Pnp Device's smartAccountId.
        type: str
      source:
        description: Pnp Device's source.
        type: str
      stack:
        description: Stack flag.
        type: bool
      stackInfo:
        description: Pnp Device's stackInfo.
        suboptions:
          isFullRing:
            description: IsFullRing flag.
            type: bool
          stackMemberList:
            description: Pnp Device's stackMemberList.
            elements: dict
            suboptions:
              hardwareVersion:
                description: Pnp Device's hardwareVersion.
                type: str
              licenseLevel:
                description: Pnp Device's licenseLevel.
                type: str
              licenseType:
                description: Pnp Device's licenseType.
                type: str
              macAddress:
                description: Pnp Device's macAddress.
                type: str
              pid:
                description: Pnp Device's pid.
                type: str
              priority:
                description: Pnp Device's priority.
                type: int
              role:
                description: Pnp Device's role.
                type: str
              serialNumber:
                description: Pnp Device's serialNumber.
                type: str
              softwareVersion:
                description: Pnp Device's softwareVersion.
                type: str
              stackNumber:
                description: Pnp Device's stackNumber.
                type: int
              state:
                description: Pnp Device's state.
                type: str
              sudiSerialNumber:
                description: Pnp Device's sudiSerialNumber.
                type: str
            type: list
          stackRingProtocol:
            description: Pnp Device's stackRingProtocol.
            type: str
          supportsStackWorkflows:
            description: SupportsStackWorkflows flag.
            type: bool
          totalMemberCount:
            description: Pnp Device's totalMemberCount.
            type: int
          validLicenseLevels:
            description: Pnp Device's validLicenseLevels.
            elements: str
            type: list
        type: dict
      state:
        description: Pnp Device's state.
        type: str
      sudiRequired:
        description: SudiRequired flag.
        type: bool
      tags:
        description: Pnp Device's tags.
        type: dict
      userSudiSerialNos:
        description: Pnp Device's userSudiSerialNos.
        elements: str
        type: list
      virtualAccountId:
        description: Pnp Device's virtualAccountId.
        type: str
      workflowId:
        description: Pnp Device's workflowId.
        type: str
      workflowName:
        description: Pnp Device's workflowName.
        type: str
    type: dict
  id:
    description: Id path parameter.
    type: str
  runSummaryList:
    description: Pnp Device's runSummaryList.
    elements: dict
    suboptions:
      details:
        description: Pnp Device's details.
        type: str
      errorFlag:
        description: ErrorFlag flag.
        type: bool
      historyTaskInfo:
        description: Pnp Device's historyTaskInfo.
        suboptions:
          addnDetails:
            description: Pnp Device's addnDetails.
            elements: dict
            suboptions:
              key:
                description: Pnp Device's key.
                type: str
              value:
                description: Pnp Device's value.
                type: str
            type: list
          name:
            description: Pnp Device's name.
            type: str
          timeTaken:
            description: Pnp Device's timeTaken.
            type: int
          type:
            description: Pnp Device's type.
            type: str
          workItemList:
            description: Pnp Device's workItemList.
            elements: dict
            suboptions:
              command:
                description: Pnp Device's command.
                type: str
              endTime:
                description: Pnp Device's endTime.
                type: int
              outputStr:
                description: Pnp Device's outputStr.
                type: str
              startTime:
                description: Pnp Device's startTime.
                type: int
              state:
                description: Pnp Device's state.
                type: str
              timeTaken:
                description: Pnp Device's timeTaken.
                type: int
            type: list
        type: dict
      timestamp:
        description: Pnp Device's timestamp.
        type: int
    type: list
  systemResetWorkflow:
    description: Pnp Device's systemResetWorkflow.
    suboptions:
      _id:
        description: Pnp Device's _id.
        type: str
      addToInventory:
        description: AddToInventory flag.
        type: bool
      addedOn:
        description: Pnp Device's addedOn.
        type: int
      configId:
        description: Pnp Device's configId.
        type: str
      currTaskIdx:
        description: Pnp Device's currTaskIdx.
        type: int
      description:
        description: Pnp Device's description.
        type: str
      endTime:
        description: Pnp Device's endTime.
        type: int
      execTime:
        description: Pnp Device's execTime.
        type: int
      imageId:
        description: Pnp Device's imageId.
        type: str
      instanceType:
        description: Pnp Device's instanceType.
        type: str
      lastupdateOn:
        description: Pnp Device's lastupdateOn.
        type: int
      name:
        description: Pnp Device's name.
        type: str
      startTime:
        description: Pnp Device's startTime.
        type: int
      state:
        description: Pnp Device's state.
        type: str
      tasks:
        description: Pnp Device's tasks.
        elements: dict
        suboptions:
          currWorkItemIdx:
            description: Pnp Device's currWorkItemIdx.
            type: int
          endTime:
            description: Pnp Device's endTime.
            type: int
          name:
            description: Pnp Device's name.
            type: str
          startTime:
            description: Pnp Device's startTime.
            type: int
          state:
            description: Pnp Device's state.
            type: str
          taskSeqNo:
            description: Pnp Device's taskSeqNo.
            type: int
          timeTaken:
            description: Pnp Device's timeTaken.
            type: int
          type:
            description: Pnp Device's type.
            type: str
          workItemList:
            description: Pnp Device's workItemList.
            elements: dict
            suboptions:
              command:
                description: Pnp Device's command.
                type: str
              endTime:
                description: Pnp Device's endTime.
                type: int
              outputStr:
                description: Pnp Device's outputStr.
                type: str
              startTime:
                description: Pnp Device's startTime.
                type: int
              state:
                description: Pnp Device's state.
                type: str
              timeTaken:
                description: Pnp Device's timeTaken.
                type: int
            type: list
        type: list
      tenantId:
        description: Pnp Device's tenantId.
        type: str
      type:
        description: Pnp Device's type.
        type: str
      useState:
        description: Pnp Device's useState.
        type: str
      version:
        description: Pnp Device's version.
        type: int
    type: dict
  systemWorkflow:
    description: Pnp Device's systemWorkflow.
    suboptions:
      _id:
        description: Pnp Device's _id.
        type: str
      addToInventory:
        description: AddToInventory flag.
        type: bool
      addedOn:
        description: Pnp Device's addedOn.
        type: int
      configId:
        description: Pnp Device's configId.
        type: str
      currTaskIdx:
        description: Pnp Device's currTaskIdx.
        type: int
      description:
        description: Pnp Device's description.
        type: str
      endTime:
        description: Pnp Device's endTime.
        type: int
      execTime:
        description: Pnp Device's execTime.
        type: int
      imageId:
        description: Pnp Device's imageId.
        type: str
      instanceType:
        description: Pnp Device's instanceType.
        type: str
      lastupdateOn:
        description: Pnp Device's lastupdateOn.
        type: int
      name:
        description: Pnp Device's name.
        type: str
      startTime:
        description: Pnp Device's startTime.
        type: int
      state:
        description: Pnp Device's state.
        type: str
      tasks:
        description: Pnp Device's tasks.
        elements: dict
        suboptions:
          currWorkItemIdx:
            description: Pnp Device's currWorkItemIdx.
            type: int
          endTime:
            description: Pnp Device's endTime.
            type: int
          name:
            description: Pnp Device's name.
            type: str
          startTime:
            description: Pnp Device's startTime.
            type: int
          state:
            description: Pnp Device's state.
            type: str
          taskSeqNo:
            description: Pnp Device's taskSeqNo.
            type: int
          timeTaken:
            description: Pnp Device's timeTaken.
            type: int
          type:
            description: Pnp Device's type.
            type: str
          workItemList:
            description: Pnp Device's workItemList.
            elements: dict
            suboptions:
              command:
                description: Pnp Device's command.
                type: str
              endTime:
                description: Pnp Device's endTime.
                type: int
              outputStr:
                description: Pnp Device's outputStr.
                type: str
              startTime:
                description: Pnp Device's startTime.
                type: int
              state:
                description: Pnp Device's state.
                type: str
              timeTaken:
                description: Pnp Device's timeTaken.
                type: int
            type: list
        type: list
      tenantId:
        description: Pnp Device's tenantId.
        type: str
      type:
        description: Pnp Device's type.
        type: str
      useState:
        description: Pnp Device's useState.
        type: str
      version:
        description: Pnp Device's version.
        type: int
    type: dict
  tenantId:
    description: Pnp Device's tenantId.
    type: str
  version:
    description: Pnp Device's version.
    type: int
  workflow:
    description: Pnp Device's workflow.
    suboptions:
      _id:
        description: Pnp Device's _id.
        type: str
      addToInventory:
        description: AddToInventory flag.
        type: bool
      addedOn:
        description: Pnp Device's addedOn.
        type: int
      configId:
        description: Pnp Device's configId.
        type: str
      currTaskIdx:
        description: Pnp Device's currTaskIdx.
        type: int
      description:
        description: Pnp Device's description.
        type: str
      endTime:
        description: Pnp Device's endTime.
        type: int
      execTime:
        description: Pnp Device's execTime.
        type: int
      imageId:
        description: Pnp Device's imageId.
        type: str
      instanceType:
        description: Pnp Device's instanceType.
        type: str
      lastupdateOn:
        description: Pnp Device's lastupdateOn.
        type: int
      name:
        description: Pnp Device's name.
        type: str
      startTime:
        description: Pnp Device's startTime.
        type: int
      state:
        description: Pnp Device's state.
        type: str
      tasks:
        description: Pnp Device's tasks.
        elements: dict
        suboptions:
          currWorkItemIdx:
            description: Pnp Device's currWorkItemIdx.
            type: int
          endTime:
            description: Pnp Device's endTime.
            type: int
          name:
            description: Pnp Device's name.
            type: str
          startTime:
            description: Pnp Device's startTime.
            type: int
          state:
            description: Pnp Device's state.
            type: str
          taskSeqNo:
            description: Pnp Device's taskSeqNo.
            type: int
          timeTaken:
            description: Pnp Device's timeTaken.
            type: int
          type:
            description: Pnp Device's type.
            type: str
          workItemList:
            description: Pnp Device's workItemList.
            elements: dict
            suboptions:
              command:
                description: Pnp Device's command.
                type: str
              endTime:
                description: Pnp Device's endTime.
                type: int
              outputStr:
                description: Pnp Device's outputStr.
                type: str
              startTime:
                description: Pnp Device's startTime.
                type: int
              state:
                description: Pnp Device's state.
                type: str
              timeTaken:
                description: Pnp Device's timeTaken.
                type: int
            type: list
        type: list
      tenantId:
        description: Pnp Device's tenantId.
        type: str
      type:
        description: Pnp Device's type.
        type: str
      useState:
        description: Pnp Device's useState.
        type: str
      version:
        description: Pnp Device's version.
        type: int
    type: dict
  workflowParameters:
    description: Pnp Device's workflowParameters.
    suboptions:
      configList:
        description: Pnp Device's configList.
        elements: dict
        suboptions:
          configId:
            description: Pnp Device's configId.
            type: str
          configParameters:
            description: Pnp Device's configParameters.
            elements: dict
            suboptions:
              key:
                description: Pnp Device's key.
                type: str
              value:
                description: Pnp Device's value.
                type: str
            type: list
        type: list
      licenseLevel:
        description: Pnp Device's licenseLevel.
        type: str
      licenseType:
        description: Pnp Device's licenseType.
        type: str
      topOfStackSerialNumber:
        description: Pnp Device's topOfStackSerialNumber.
        type: str
    type: dict
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Device Onboarding (PnP) AddDevice
  description: Complete reference of the AddDevice API.
  link: https://developer.cisco.com/docs/dna-center/#!add-device-2
- name: Cisco DNA Center documentation for Device Onboarding (PnP) DeleteDeviceByIdFromPnP
  description: Complete reference of the DeleteDeviceByIdFromPnP API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-device-by-id-from-pn-p
- name: Cisco DNA Center documentation for Device Onboarding (PnP) UpdateDevice
  description: Complete reference of the UpdateDevice API.
  link: https://developer.cisco.com/docs/dna-center/#!update-device
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.add_device,
    device_onboarding_pnp.DeviceOnboardingPnp.delete_device_by_id_from_pnp,
    device_onboarding_pnp.DeviceOnboardingPnp.update_device,

  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device,
    delete /dna/intent/api/v1/onboarding/pnp-device/{id},
    put /dna/intent/api/v1/onboarding/pnp-device/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.pnp_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    _id: string
    deviceInfo:
      aaaCredentials:
        password: string
        username: string
      addedOn: 0
      addnMacAddrs:
      - string
      agentType: string
      authStatus: string
      authenticatedSudiSerialNo: string
      capabilitiesSupported:
      - string
      cmState: string
      description: string
      deviceSudiSerialNos:
      - string
      deviceType: string
      featuresSupported:
      - string
      fileSystemList:
      - freespace: 0
        name: string
        readable: true
        size: 0
        type: string
        writeable: true
      firstContact: 0
      hostname: string
      httpHeaders:
      - key: string
        value: string
      imageFile: string
      imageVersion: string
      ipInterfaces:
      - ipv4Address: {}
        ipv6AddressList:
        - {}
        macAddress: string
        name: string
        status: string
      lastContact: 0
      lastSyncTime: 0
      lastUpdateOn: 0
      location:
        address: string
        altitude: string
        latitude: string
        longitude: string
        siteId: string
      macAddress: string
      mode: string
      name: string
      neighborLinks:
      - localInterfaceName: string
        localMacAddress: string
        localShortInterfaceName: string
        remoteDeviceName: string
        remoteInterfaceName: string
        remoteMacAddress: string
        remotePlatform: string
        remoteShortInterfaceName: string
        remoteVersion: string
      onbState: string
      pid: string
      pnpProfileList:
      - createdBy: string
        discoveryCreated: true
        primaryEndpoint:
          certificate: string
          fqdn: string
          ipv4Address: {}
          ipv6Address: {}
          port: 0
          protocol: string
        profileName: string
        secondaryEndpoint:
          certificate: string
          fqdn: string
          ipv4Address: {}
          ipv6Address: {}
          port: 0
          protocol: string
      populateInventory: true
      preWorkflowCliOuputs:
      - cli: string
        cliOutput: string
      projectId: string
      projectName: string
      reloadRequested: true
      serialNumber: string
      smartAccountId: string
      source: string
      stack: true
      stackInfo:
        isFullRing: true
        stackMemberList:
        - hardwareVersion: string
          licenseLevel: string
          licenseType: string
          macAddress: string
          pid: string
          priority: 0
          role: string
          serialNumber: string
          softwareVersion: string
          stackNumber: 0
          state: string
          sudiSerialNumber: string
        stackRingProtocol: string
        supportsStackWorkflows: true
        totalMemberCount: 0
        validLicenseLevels:
        - string
      state: string
      sudiRequired: true
      tags: {}
      userSudiSerialNos:
      - string
      virtualAccountId: string
      workflowId: string
      workflowName: string
    runSummaryList:
    - details: string
      errorFlag: true
      historyTaskInfo:
        addnDetails:
        - key: string
          value: string
        name: string
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      timestamp: 0
    systemResetWorkflow:
      _id: string
      addToInventory: true
      addedOn: 0
      configId: string
      currTaskIdx: 0
      description: string
      endTime: 0
      execTime: 0
      imageId: string
      instanceType: string
      lastupdateOn: 0
      name: string
      startTime: 0
      state: string
      tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      tenantId: string
      type: string
      useState: string
      version: 0
    systemWorkflow:
      _id: string
      addToInventory: true
      addedOn: 0
      configId: string
      currTaskIdx: 0
      description: string
      endTime: 0
      execTime: 0
      imageId: string
      instanceType: string
      lastupdateOn: 0
      name: string
      startTime: 0
      state: string
      tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      tenantId: string
      type: string
      useState: string
      version: 0
    tenantId: string
    version: 0
    workflow:
      _id: string
      addToInventory: true
      addedOn: 0
      configId: string
      currTaskIdx: 0
      description: string
      endTime: 0
      execTime: 0
      imageId: string
      instanceType: string
      lastupdateOn: 0
      name: string
      startTime: 0
      state: string
      tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      tenantId: string
      type: string
      useState: string
      version: 0
    workflowParameters:
      configList:
      - configId: string
        configParameters:
        - key: string
          value: string
      licenseLevel: string
      licenseType: string
      topOfStackSerialNumber: string

- name: Update by id
  cisco.dnac.pnp_device:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    _id: string
    deviceInfo:
      aaaCredentials:
        password: string
        username: string
      addedOn: 0
      addnMacAddrs:
      - string
      agentType: string
      authStatus: string
      authenticatedSudiSerialNo: string
      capabilitiesSupported:
      - string
      cmState: string
      description: string
      deviceSudiSerialNos:
      - string
      deviceType: string
      featuresSupported:
      - string
      fileSystemList:
      - freespace: 0
        name: string
        readable: true
        size: 0
        type: string
        writeable: true
      firstContact: 0
      hostname: string
      httpHeaders:
      - key: string
        value: string
      imageFile: string
      imageVersion: string
      ipInterfaces:
      - ipv4Address: {}
        ipv6AddressList:
        - {}
        macAddress: string
        name: string
        status: string
      lastContact: 0
      lastSyncTime: 0
      lastUpdateOn: 0
      location:
        address: string
        altitude: string
        latitude: string
        longitude: string
        siteId: string
      macAddress: string
      mode: string
      name: string
      neighborLinks:
      - localInterfaceName: string
        localMacAddress: string
        localShortInterfaceName: string
        remoteDeviceName: string
        remoteInterfaceName: string
        remoteMacAddress: string
        remotePlatform: string
        remoteShortInterfaceName: string
        remoteVersion: string
      onbState: string
      pid: string
      pnpProfileList:
      - createdBy: string
        discoveryCreated: true
        primaryEndpoint:
          certificate: string
          fqdn: string
          ipv4Address: {}
          ipv6Address: {}
          port: 0
          protocol: string
        profileName: string
        secondaryEndpoint:
          certificate: string
          fqdn: string
          ipv4Address: {}
          ipv6Address: {}
          port: 0
          protocol: string
      populateInventory: true
      preWorkflowCliOuputs:
      - cli: string
        cliOutput: string
      projectId: string
      projectName: string
      reloadRequested: true
      serialNumber: string
      smartAccountId: string
      source: string
      stack: true
      stackInfo:
        isFullRing: true
        stackMemberList:
        - hardwareVersion: string
          licenseLevel: string
          licenseType: string
          macAddress: string
          pid: string
          priority: 0
          role: string
          serialNumber: string
          softwareVersion: string
          stackNumber: 0
          state: string
          sudiSerialNumber: string
        stackRingProtocol: string
        supportsStackWorkflows: true
        totalMemberCount: 0
        validLicenseLevels:
        - string
      state: string
      sudiRequired: true
      tags: {}
      userSudiSerialNos:
      - string
      virtualAccountId: string
      workflowId: string
      workflowName: string
    id: string
    runSummaryList:
    - details: string
      errorFlag: true
      historyTaskInfo:
        addnDetails:
        - key: string
          value: string
        name: string
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      timestamp: 0
    systemResetWorkflow:
      _id: string
      addToInventory: true
      addedOn: 0
      configId: string
      currTaskIdx: 0
      description: string
      endTime: 0
      execTime: 0
      imageId: string
      instanceType: string
      lastupdateOn: 0
      name: string
      startTime: 0
      state: string
      tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      tenantId: string
      type: string
      useState: string
      version: 0
    systemWorkflow:
      _id: string
      addToInventory: true
      addedOn: 0
      configId: string
      currTaskIdx: 0
      description: string
      endTime: 0
      execTime: 0
      imageId: string
      instanceType: string
      lastupdateOn: 0
      name: string
      startTime: 0
      state: string
      tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      tenantId: string
      type: string
      useState: string
      version: 0
    tenantId: string
    version: 0
    workflow:
      _id: string
      addToInventory: true
      addedOn: 0
      configId: string
      currTaskIdx: 0
      description: string
      endTime: 0
      execTime: 0
      imageId: string
      instanceType: string
      lastupdateOn: 0
      name: string
      startTime: 0
      state: string
      tasks:
      - currWorkItemIdx: 0
        endTime: 0
        name: string
        startTime: 0
        state: string
        taskSeqNo: 0
        timeTaken: 0
        type: string
        workItemList:
        - command: string
          endTime: 0
          outputStr: string
          startTime: 0
          state: string
          timeTaken: 0
      tenantId: string
      type: string
      useState: string
      version: 0
    workflowParameters:
      configList:
      - configId: string
        configParameters:
        - key: string
          value: string
      licenseLevel: string
      licenseType: string
      topOfStackSerialNumber: string

- name: Delete by id
  cisco.dnac.pnp_device:
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
      "_id": "string",
      "deviceInfo": {
        "source": "string",
        "serialNumber": "string",
        "stack": true,
        "mode": "string",
        "state": "string",
        "location": {
          "siteId": "string",
          "address": "string",
          "latitude": "string",
          "longitude": "string",
          "altitude": "string"
        },
        "description": "string",
        "onbState": "string",
        "authenticatedMicNumber": "string",
        "authenticatedSudiSerialNo": "string",
        "capabilitiesSupported": [
          "string"
        ],
        "featuresSupported": [
          "string"
        ],
        "cmState": "string",
        "firstContact": 0,
        "lastContact": 0,
        "macAddress": "string",
        "pid": "string",
        "deviceSudiSerialNos": [
          "string"
        ],
        "lastUpdateOn": 0,
        "workflowId": "string",
        "workflowName": "string",
        "projectId": "string",
        "projectName": "string",
        "deviceType": "string",
        "agentType": "string",
        "imageVersion": "string",
        "fileSystemList": [
          {
            "type": "string",
            "writeable": true,
            "freespace": 0,
            "name": "string",
            "readable": true,
            "size": 0
          }
        ],
        "pnpProfileList": [
          {
            "profileName": "string",
            "discoveryCreated": true,
            "createdBy": "string",
            "primaryEndpoint": {
              "port": 0,
              "protocol": "string",
              "ipv4Address": {},
              "ipv6Address": {},
              "fqdn": "string",
              "certificate": "string"
            },
            "secondaryEndpoint": {
              "port": 0,
              "protocol": "string",
              "ipv4Address": {},
              "ipv6Address": {},
              "fqdn": "string",
              "certificate": "string"
            }
          }
        ],
        "imageFile": "string",
        "httpHeaders": [
          {
            "key": "string",
            "value": "string"
          }
        ],
        "neighborLinks": [
          {
            "localInterfaceName": "string",
            "localShortInterfaceName": "string",
            "localMacAddress": "string",
            "remoteInterfaceName": "string",
            "remoteShortInterfaceName": "string",
            "remoteMacAddress": "string",
            "remoteDeviceName": "string",
            "remotePlatform": "string",
            "remoteVersion": "string"
          }
        ],
        "lastSyncTime": 0,
        "ipInterfaces": [
          {
            "status": "string",
            "macAddress": "string",
            "ipv4Address": {},
            "ipv6AddressList": [
              {}
            ],
            "name": "string"
          }
        ],
        "hostname": "string",
        "authStatus": "string",
        "stackInfo": {
          "supportsStackWorkflows": true,
          "isFullRing": true,
          "stackMemberList": [
            {
              "serialNumber": "string",
              "state": "string",
              "role": "string",
              "macAddress": "string",
              "pid": "string",
              "licenseLevel": "string",
              "licenseType": "string",
              "sudiSerialNumber": "string",
              "hardwareVersion": "string",
              "stackNumber": 0,
              "softwareVersion": "string",
              "priority": 0
            }
          ],
          "stackRingProtocol": "string",
          "validLicenseLevels": [
            "string"
          ],
          "totalMemberCount": 0
        },
        "reloadRequested": true,
        "addedOn": 0,
        "siteId": "string",
        "aaaCredentials": {
          "password": "string",
          "username": "string"
        },
        "userMicNumbers": [
          "string"
        ],
        "userSudiSerialNos": [
          "string"
        ],
        "addnMacAddrs": [
          "string"
        ],
        "preWorkflowCliOuputs": [
          {
            "cli": "string",
            "cliOutput": "string"
          }
        ],
        "tags": {},
        "sudiRequired": true,
        "smartAccountId": "string",
        "virtualAccountId": "string",
        "populateInventory": true,
        "siteName": "string",
        "name": "string"
      },
      "systemResetWorkflow": {
        "_id": "string",
        "state": "string",
        "type": "string",
        "description": "string",
        "lastupdateOn": 0,
        "imageId": "string",
        "currTaskIdx": 0,
        "addedOn": 0,
        "tasks": [
          {
            "state": "string",
            "type": "string",
            "currWorkItemIdx": 0,
            "taskSeqNo": 0,
            "endTime": 0,
            "startTime": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "name": "string"
          }
        ],
        "addToInventory": true,
        "instanceType": "string",
        "endTime": 0,
        "execTime": 0,
        "startTime": 0,
        "useState": "string",
        "configId": "string",
        "name": "string",
        "version": 0,
        "tenantId": "string"
      },
      "systemWorkflow": {
        "_id": "string",
        "state": "string",
        "type": "string",
        "description": "string",
        "lastupdateOn": 0,
        "imageId": "string",
        "currTaskIdx": 0,
        "addedOn": 0,
        "tasks": [
          {
            "state": "string",
            "type": "string",
            "currWorkItemIdx": 0,
            "taskSeqNo": 0,
            "endTime": 0,
            "startTime": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "name": "string"
          }
        ],
        "addToInventory": true,
        "instanceType": "string",
        "endTime": 0,
        "execTime": 0,
        "startTime": 0,
        "useState": "string",
        "configId": "string",
        "name": "string",
        "version": 0,
        "tenantId": "string"
      },
      "workflow": {
        "_id": "string",
        "state": "string",
        "type": "string",
        "description": "string",
        "lastupdateOn": 0,
        "imageId": "string",
        "currTaskIdx": 0,
        "addedOn": 0,
        "tasks": [
          {
            "state": "string",
            "type": "string",
            "currWorkItemIdx": 0,
            "taskSeqNo": 0,
            "endTime": 0,
            "startTime": 0,
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "name": "string"
          }
        ],
        "addToInventory": true,
        "instanceType": "string",
        "endTime": 0,
        "execTime": 0,
        "startTime": 0,
        "useState": "string",
        "configId": "string",
        "name": "string",
        "version": 0,
        "tenantId": "string"
      },
      "runSummaryList": [
        {
          "details": "string",
          "historyTaskInfo": {
            "type": "string",
            "workItemList": [
              {
                "state": "string",
                "command": "string",
                "outputStr": "string",
                "endTime": 0,
                "startTime": 0,
                "timeTaken": 0
              }
            ],
            "timeTaken": 0,
            "addnDetails": [
              {
                "key": "string",
                "value": "string"
              }
            ],
            "name": "string"
          },
          "errorFlag": true,
          "timestamp": 0
        }
      ],
      "workflowParameters": {
        "topOfStackSerialNumber": "string",
        "licenseLevel": "string",
        "licenseType": "string",
        "configList": [
          {
            "configParameters": [
              {
                "key": "string",
                "value": "string"
              }
            ],
            "configId": "string"
          }
        ]
      },
      "dayZeroConfig": {
        "config": "string"
      },
      "dayZeroConfigPreview": {},
      "version": 0,
      "tenantId": "string"
    }
"""
