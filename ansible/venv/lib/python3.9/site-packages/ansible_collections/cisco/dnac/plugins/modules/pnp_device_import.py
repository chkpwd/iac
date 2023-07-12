#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pnp_device_import
short_description: Resource module for Pnp Device Import
description:
- Manage operation create of the resource Pnp Device Import.
- Add devices to PnP in bulk.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Pnp Device Import's payload.
    elements: dict
    suboptions:
      _id:
        description: Pnp Device Import's _id.
        type: str
      deviceInfo:
        description: Pnp Device Import's deviceInfo.
        suboptions:
          aaaCredentials:
            description: Pnp Device Import's aaaCredentials.
            suboptions:
              password:
                description: Pnp Device Import's password.
                type: str
              username:
                description: Pnp Device Import's username.
                type: str
            type: dict
          addedOn:
            description: Pnp Device Import's addedOn.
            type: int
          addnMacAddrs:
            description: Pnp Device Import's addnMacAddrs.
            elements: str
            type: list
          agentType:
            description: Pnp Device Import's agentType.
            type: str
          authStatus:
            description: Pnp Device Import's authStatus.
            type: str
          authenticatedSudiSerialNo:
            description: Pnp Device Import's authenticatedSudiSerialNo.
            type: str
          capabilitiesSupported:
            description: Pnp Device Import's capabilitiesSupported.
            elements: str
            type: list
          cmState:
            description: Pnp Device Import's cmState.
            type: str
          description:
            description: Pnp Device Import's description.
            type: str
          deviceSudiSerialNos:
            description: Pnp Device Import's deviceSudiSerialNos.
            elements: str
            type: list
          deviceType:
            description: Pnp Device Import's deviceType.
            type: str
          featuresSupported:
            description: Pnp Device Import's featuresSupported.
            elements: str
            type: list
          fileSystemList:
            description: Pnp Device Import's fileSystemList.
            elements: dict
            suboptions:
              freespace:
                description: Pnp Device Import's freespace.
                type: int
              name:
                description: Pnp Device Import's name.
                type: str
              readable:
                description: Readable flag.
                type: bool
              size:
                description: Pnp Device Import's size.
                type: int
              type:
                description: Pnp Device Import's type.
                type: str
              writeable:
                description: Writeable flag.
                type: bool
            type: list
          firstContact:
            description: Pnp Device Import's firstContact.
            type: int
          hostname:
            description: Pnp Device Import's hostname.
            type: str
          httpHeaders:
            description: Pnp Device Import's httpHeaders.
            elements: dict
            suboptions:
              key:
                description: Pnp Device Import's key.
                type: str
              value:
                description: Pnp Device Import's value.
                type: str
            type: list
          imageFile:
            description: Pnp Device Import's imageFile.
            type: str
          imageVersion:
            description: Pnp Device Import's imageVersion.
            type: str
          ipInterfaces:
            description: Pnp Device Import's ipInterfaces.
            elements: dict
            suboptions:
              ipv4Address:
                description: Pnp Device Import's ipv4Address.
                type: dict
              ipv6AddressList:
                description: Pnp Device Import's ipv6AddressList.
                elements: dict
                type: list
              macAddress:
                description: Pnp Device Import's macAddress.
                type: str
              name:
                description: Pnp Device Import's name.
                type: str
              status:
                description: Pnp Device Import's status.
                type: str
            type: list
          lastContact:
            description: Pnp Device Import's lastContact.
            type: int
          lastSyncTime:
            description: Pnp Device Import's lastSyncTime.
            type: int
          lastUpdateOn:
            description: Pnp Device Import's lastUpdateOn.
            type: int
          location:
            description: Pnp Device Import's location.
            suboptions:
              address:
                description: Pnp Device Import's address.
                type: str
              altitude:
                description: Pnp Device Import's altitude.
                type: str
              latitude:
                description: Pnp Device Import's latitude.
                type: str
              longitude:
                description: Pnp Device Import's longitude.
                type: str
              siteId:
                description: Pnp Device Import's siteId.
                type: str
            type: dict
          macAddress:
            description: Pnp Device Import's macAddress.
            type: str
          mode:
            description: Pnp Device Import's mode.
            type: str
          name:
            description: Pnp Device Import's name.
            type: str
          neighborLinks:
            description: Pnp Device Import's neighborLinks.
            elements: dict
            suboptions:
              localInterfaceName:
                description: Pnp Device Import's localInterfaceName.
                type: str
              localMacAddress:
                description: Pnp Device Import's localMacAddress.
                type: str
              localShortInterfaceName:
                description: Pnp Device Import's localShortInterfaceName.
                type: str
              remoteDeviceName:
                description: Pnp Device Import's remoteDeviceName.
                type: str
              remoteInterfaceName:
                description: Pnp Device Import's remoteInterfaceName.
                type: str
              remoteMacAddress:
                description: Pnp Device Import's remoteMacAddress.
                type: str
              remotePlatform:
                description: Pnp Device Import's remotePlatform.
                type: str
              remoteShortInterfaceName:
                description: Pnp Device Import's remoteShortInterfaceName.
                type: str
              remoteVersion:
                description: Pnp Device Import's remoteVersion.
                type: str
            type: list
          onbState:
            description: Pnp Device Import's onbState.
            type: str
          pid:
            description: Pnp Device Import's pid.
            type: str
          pnpProfileList:
            description: Pnp Device Import's pnpProfileList.
            elements: dict
            suboptions:
              createdBy:
                description: Pnp Device Import's createdBy.
                type: str
              discoveryCreated:
                description: DiscoveryCreated flag.
                type: bool
              primaryEndpoint:
                description: Pnp Device Import's primaryEndpoint.
                suboptions:
                  certificate:
                    description: Pnp Device Import's certificate.
                    type: str
                  fqdn:
                    description: Pnp Device Import's fqdn.
                    type: str
                  ipv4Address:
                    description: Pnp Device Import's ipv4Address.
                    type: dict
                  ipv6Address:
                    description: Pnp Device Import's ipv6Address.
                    type: dict
                  port:
                    description: Pnp Device Import's port.
                    type: int
                  protocol:
                    description: Pnp Device Import's protocol.
                    type: str
                type: dict
              profileName:
                description: Pnp Device Import's profileName.
                type: str
              secondaryEndpoint:
                description: Pnp Device Import's secondaryEndpoint.
                suboptions:
                  certificate:
                    description: Pnp Device Import's certificate.
                    type: str
                  fqdn:
                    description: Pnp Device Import's fqdn.
                    type: str
                  ipv4Address:
                    description: Pnp Device Import's ipv4Address.
                    type: dict
                  ipv6Address:
                    description: Pnp Device Import's ipv6Address.
                    type: dict
                  port:
                    description: Pnp Device Import's port.
                    type: int
                  protocol:
                    description: Pnp Device Import's protocol.
                    type: str
                type: dict
            type: list
          populateInventory:
            description: PopulateInventory flag.
            type: bool
          preWorkflowCliOuputs:
            description: Pnp Device Import's preWorkflowCliOuputs.
            elements: dict
            suboptions:
              cli:
                description: Pnp Device Import's cli.
                type: str
              cliOutput:
                description: Pnp Device Import's cliOutput.
                type: str
            type: list
          projectId:
            description: Pnp Device Import's projectId.
            type: str
          projectName:
            description: Pnp Device Import's projectName.
            type: str
          reloadRequested:
            description: ReloadRequested flag.
            type: bool
          serialNumber:
            description: Pnp Device Import's serialNumber.
            type: str
          smartAccountId:
            description: Pnp Device Import's smartAccountId.
            type: str
          source:
            description: Pnp Device Import's source.
            type: str
          stack:
            description: Stack flag.
            type: bool
          stackInfo:
            description: Pnp Device Import's stackInfo.
            suboptions:
              isFullRing:
                description: IsFullRing flag.
                type: bool
              stackMemberList:
                description: Pnp Device Import's stackMemberList.
                elements: dict
                suboptions:
                  hardwareVersion:
                    description: Pnp Device Import's hardwareVersion.
                    type: str
                  licenseLevel:
                    description: Pnp Device Import's licenseLevel.
                    type: str
                  licenseType:
                    description: Pnp Device Import's licenseType.
                    type: str
                  macAddress:
                    description: Pnp Device Import's macAddress.
                    type: str
                  pid:
                    description: Pnp Device Import's pid.
                    type: str
                  priority:
                    description: Pnp Device Import's priority.
                    type: int
                  role:
                    description: Pnp Device Import's role.
                    type: str
                  serialNumber:
                    description: Pnp Device Import's serialNumber.
                    type: str
                  softwareVersion:
                    description: Pnp Device Import's softwareVersion.
                    type: str
                  stackNumber:
                    description: Pnp Device Import's stackNumber.
                    type: int
                  state:
                    description: Pnp Device Import's state.
                    type: str
                  sudiSerialNumber:
                    description: Pnp Device Import's sudiSerialNumber.
                    type: str
                type: list
              stackRingProtocol:
                description: Pnp Device Import's stackRingProtocol.
                type: str
              supportsStackWorkflows:
                description: SupportsStackWorkflows flag.
                type: bool
              totalMemberCount:
                description: Pnp Device Import's totalMemberCount.
                type: int
              validLicenseLevels:
                description: Pnp Device Import's validLicenseLevels.
                elements: str
                type: list
            type: dict
          state:
            description: Pnp Device Import's state.
            type: str
          sudiRequired:
            description: SudiRequired flag.
            type: bool
          tags:
            description: Pnp Device Import's tags.
            type: dict
          userSudiSerialNos:
            description: Pnp Device Import's userSudiSerialNos.
            elements: str
            type: list
          virtualAccountId:
            description: Pnp Device Import's virtualAccountId.
            type: str
          workflowId:
            description: Pnp Device Import's workflowId.
            type: str
          workflowName:
            description: Pnp Device Import's workflowName.
            type: str
        type: dict
      runSummaryList:
        description: Pnp Device Import's runSummaryList.
        elements: dict
        suboptions:
          details:
            description: Pnp Device Import's details.
            type: str
          errorFlag:
            description: ErrorFlag flag.
            type: bool
          historyTaskInfo:
            description: Pnp Device Import's historyTaskInfo.
            suboptions:
              addnDetails:
                description: Pnp Device Import's addnDetails.
                elements: dict
                suboptions:
                  key:
                    description: Pnp Device Import's key.
                    type: str
                  value:
                    description: Pnp Device Import's value.
                    type: str
                type: list
              name:
                description: Pnp Device Import's name.
                type: str
              timeTaken:
                description: Pnp Device Import's timeTaken.
                type: int
              type:
                description: Pnp Device Import's type.
                type: str
              workItemList:
                description: Pnp Device Import's workItemList.
                elements: dict
                suboptions:
                  command:
                    description: Pnp Device Import's command.
                    type: str
                  endTime:
                    description: Pnp Device Import's endTime.
                    type: int
                  outputStr:
                    description: Pnp Device Import's outputStr.
                    type: str
                  startTime:
                    description: Pnp Device Import's startTime.
                    type: int
                  state:
                    description: Pnp Device Import's state.
                    type: str
                  timeTaken:
                    description: Pnp Device Import's timeTaken.
                    type: int
                type: list
            type: dict
          timestamp:
            description: Pnp Device Import's timestamp.
            type: int
        type: list
      systemResetWorkflow:
        description: Pnp Device Import's systemResetWorkflow.
        suboptions:
          _id:
            description: Pnp Device Import's _id.
            type: str
          addToInventory:
            description: AddToInventory flag.
            type: bool
          addedOn:
            description: Pnp Device Import's addedOn.
            type: int
          configId:
            description: Pnp Device Import's configId.
            type: str
          currTaskIdx:
            description: Pnp Device Import's currTaskIdx.
            type: int
          description:
            description: Pnp Device Import's description.
            type: str
          endTime:
            description: Pnp Device Import's endTime.
            type: int
          execTime:
            description: Pnp Device Import's execTime.
            type: int
          imageId:
            description: Pnp Device Import's imageId.
            type: str
          instanceType:
            description: Pnp Device Import's instanceType.
            type: str
          lastupdateOn:
            description: Pnp Device Import's lastupdateOn.
            type: int
          name:
            description: Pnp Device Import's name.
            type: str
          startTime:
            description: Pnp Device Import's startTime.
            type: int
          state:
            description: Pnp Device Import's state.
            type: str
          tasks:
            description: Pnp Device Import's tasks.
            elements: dict
            suboptions:
              currWorkItemIdx:
                description: Pnp Device Import's currWorkItemIdx.
                type: int
              endTime:
                description: Pnp Device Import's endTime.
                type: int
              name:
                description: Pnp Device Import's name.
                type: str
              startTime:
                description: Pnp Device Import's startTime.
                type: int
              state:
                description: Pnp Device Import's state.
                type: str
              taskSeqNo:
                description: Pnp Device Import's taskSeqNo.
                type: int
              timeTaken:
                description: Pnp Device Import's timeTaken.
                type: int
              type:
                description: Pnp Device Import's type.
                type: str
              workItemList:
                description: Pnp Device Import's workItemList.
                elements: dict
                suboptions:
                  command:
                    description: Pnp Device Import's command.
                    type: str
                  endTime:
                    description: Pnp Device Import's endTime.
                    type: int
                  outputStr:
                    description: Pnp Device Import's outputStr.
                    type: str
                  startTime:
                    description: Pnp Device Import's startTime.
                    type: int
                  state:
                    description: Pnp Device Import's state.
                    type: str
                  timeTaken:
                    description: Pnp Device Import's timeTaken.
                    type: int
                type: list
            type: list
          tenantId:
            description: Pnp Device Import's tenantId.
            type: str
          type:
            description: Pnp Device Import's type.
            type: str
          useState:
            description: Pnp Device Import's useState.
            type: str
          version:
            description: Pnp Device Import's version.
            type: int
        type: dict
      systemWorkflow:
        description: Pnp Device Import's systemWorkflow.
        suboptions:
          _id:
            description: Pnp Device Import's _id.
            type: str
          addToInventory:
            description: AddToInventory flag.
            type: bool
          addedOn:
            description: Pnp Device Import's addedOn.
            type: int
          configId:
            description: Pnp Device Import's configId.
            type: str
          currTaskIdx:
            description: Pnp Device Import's currTaskIdx.
            type: int
          description:
            description: Pnp Device Import's description.
            type: str
          endTime:
            description: Pnp Device Import's endTime.
            type: int
          execTime:
            description: Pnp Device Import's execTime.
            type: int
          imageId:
            description: Pnp Device Import's imageId.
            type: str
          instanceType:
            description: Pnp Device Import's instanceType.
            type: str
          lastupdateOn:
            description: Pnp Device Import's lastupdateOn.
            type: int
          name:
            description: Pnp Device Import's name.
            type: str
          startTime:
            description: Pnp Device Import's startTime.
            type: int
          state:
            description: Pnp Device Import's state.
            type: str
          tasks:
            description: Pnp Device Import's tasks.
            elements: dict
            suboptions:
              currWorkItemIdx:
                description: Pnp Device Import's currWorkItemIdx.
                type: int
              endTime:
                description: Pnp Device Import's endTime.
                type: int
              name:
                description: Pnp Device Import's name.
                type: str
              startTime:
                description: Pnp Device Import's startTime.
                type: int
              state:
                description: Pnp Device Import's state.
                type: str
              taskSeqNo:
                description: Pnp Device Import's taskSeqNo.
                type: int
              timeTaken:
                description: Pnp Device Import's timeTaken.
                type: int
              type:
                description: Pnp Device Import's type.
                type: str
              workItemList:
                description: Pnp Device Import's workItemList.
                elements: dict
                suboptions:
                  command:
                    description: Pnp Device Import's command.
                    type: str
                  endTime:
                    description: Pnp Device Import's endTime.
                    type: int
                  outputStr:
                    description: Pnp Device Import's outputStr.
                    type: str
                  startTime:
                    description: Pnp Device Import's startTime.
                    type: int
                  state:
                    description: Pnp Device Import's state.
                    type: str
                  timeTaken:
                    description: Pnp Device Import's timeTaken.
                    type: int
                type: list
            type: list
          tenantId:
            description: Pnp Device Import's tenantId.
            type: str
          type:
            description: Pnp Device Import's type.
            type: str
          useState:
            description: Pnp Device Import's useState.
            type: str
          version:
            description: Pnp Device Import's version.
            type: int
        type: dict
      tenantId:
        description: Pnp Device Import's tenantId.
        type: str
      version:
        description: Pnp Device Import's version.
        type: int
      workflow:
        description: Pnp Device Import's workflow.
        suboptions:
          _id:
            description: Pnp Device Import's _id.
            type: str
          addToInventory:
            description: AddToInventory flag.
            type: bool
          addedOn:
            description: Pnp Device Import's addedOn.
            type: int
          configId:
            description: Pnp Device Import's configId.
            type: str
          currTaskIdx:
            description: Pnp Device Import's currTaskIdx.
            type: int
          description:
            description: Pnp Device Import's description.
            type: str
          endTime:
            description: Pnp Device Import's endTime.
            type: int
          execTime:
            description: Pnp Device Import's execTime.
            type: int
          imageId:
            description: Pnp Device Import's imageId.
            type: str
          instanceType:
            description: Pnp Device Import's instanceType.
            type: str
          lastupdateOn:
            description: Pnp Device Import's lastupdateOn.
            type: int
          name:
            description: Pnp Device Import's name.
            type: str
          startTime:
            description: Pnp Device Import's startTime.
            type: int
          state:
            description: Pnp Device Import's state.
            type: str
          tasks:
            description: Pnp Device Import's tasks.
            elements: dict
            suboptions:
              currWorkItemIdx:
                description: Pnp Device Import's currWorkItemIdx.
                type: int
              endTime:
                description: Pnp Device Import's endTime.
                type: int
              name:
                description: Pnp Device Import's name.
                type: str
              startTime:
                description: Pnp Device Import's startTime.
                type: int
              state:
                description: Pnp Device Import's state.
                type: str
              taskSeqNo:
                description: Pnp Device Import's taskSeqNo.
                type: int
              timeTaken:
                description: Pnp Device Import's timeTaken.
                type: int
              type:
                description: Pnp Device Import's type.
                type: str
              workItemList:
                description: Pnp Device Import's workItemList.
                elements: dict
                suboptions:
                  command:
                    description: Pnp Device Import's command.
                    type: str
                  endTime:
                    description: Pnp Device Import's endTime.
                    type: int
                  outputStr:
                    description: Pnp Device Import's outputStr.
                    type: str
                  startTime:
                    description: Pnp Device Import's startTime.
                    type: int
                  state:
                    description: Pnp Device Import's state.
                    type: str
                  timeTaken:
                    description: Pnp Device Import's timeTaken.
                    type: int
                type: list
            type: list
          tenantId:
            description: Pnp Device Import's tenantId.
            type: str
          type:
            description: Pnp Device Import's type.
            type: str
          useState:
            description: Pnp Device Import's useState.
            type: str
          version:
            description: Pnp Device Import's version.
            type: int
        type: dict
      workflowParameters:
        description: Pnp Device Import's workflowParameters.
        suboptions:
          configList:
            description: Pnp Device Import's configList.
            elements: dict
            suboptions:
              configId:
                description: Pnp Device Import's configId.
                type: str
              configParameters:
                description: Pnp Device Import's configParameters.
                elements: dict
                suboptions:
                  key:
                    description: Pnp Device Import's key.
                    type: str
                  value:
                    description: Pnp Device Import's value.
                    type: str
                type: list
            type: list
          licenseLevel:
            description: Pnp Device Import's licenseLevel.
            type: str
          licenseType:
            description: Pnp Device Import's licenseType.
            type: str
          topOfStackSerialNumber:
            description: Pnp Device Import's topOfStackSerialNumber.
            type: str
        type: dict
    type: list
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Device Onboarding (PnP) ImportDevicesInBulk
  description: Complete reference of the ImportDevicesInBulk API.
  link: https://developer.cisco.com/docs/dna-center/#!import-devices-in-bulk
notes:
  - SDK Method used are
    device_onboarding_pnp.DeviceOnboardingPnp.import_devices_in_bulk,

  - Paths used are
    post /dna/intent/api/v1/onboarding/pnp-device/import,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.pnp_device_import:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
    - _id: string
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

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "successList": [
        {
          "_id": "string",
          "id": "string",
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
      ],
      "failureList": [
        {
          "index": 0,
          "serialNum": "string",
          "id": "string",
          "msg": "string"
        }
      ]
    }
"""
