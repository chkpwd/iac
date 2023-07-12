#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nfv_profile
short_description: Resource module for Nfv Profile
description:
- Manage operations create, update and delete of the resource Nfv Profile.
- API to create network profile for different NFV topologies.
- API to delete nfv network profile.
- API to update a NFV Network profile.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device:
    description: Nfv Profile's device.
    elements: dict
    suboptions:
      customNetworks:
        description: Nfv Profile's customNetworks.
        elements: dict
        suboptions:
          connectionType:
            description: Type of network connection from custom network (eg lan).
            type: str
          networkName:
            description: Name of custom network (eg cust-1).
            type: str
          servicesToConnect:
            description: Nfv Profile's servicesToConnect.
            elements: dict
            suboptions:
              serviceName:
                description: Name of service to be connected to the custom network (eg
                  router-1).
                type: str
            type: list
          vlanId:
            description: Vlan id for the custom network(eg 4000).
            type: int
          vlanMode:
            description: Network mode (eg Access or Trunk).
            type: str
        type: list
      customTemplate:
        description: Nfv Profile's customTemplate.
        elements: dict
        suboptions:
          deviceType:
            description: Type of the device(eg Cisco 5400 Enterprise Network Compute
              System).
            type: str
          template:
            description: Name of the template(eg NFVIS template).
            type: str
          templateType:
            description: Name of the template type to which template is associated (eg
              Cloud DayN Templates).
            type: str
        type: list
      deviceTag:
        description: Device Tag name(eg dev1).
        type: str
      deviceType:
        description: Name of the device used in creating nfv profile.
        type: str
      directInternetAccessForFirewall:
        description: Direct internet access value should be boolean (eg false or true).
        type: bool
      serviceProviderProfile:
        description: Nfv Profile's serviceProviderProfile.
        elements: dict
        suboptions:
          connect:
            description: Connection of service provider and device value should be boolean
              (eg true).
            type: bool
          connectDefaultGatewayOnWan:
            description: Connect default gateway connect value as boolean (eg true).
            type: bool
          linkType:
            description: Name of connection type(eg GigabitEthernet).
            type: str
          serviceProvider:
            description: Name of the service provider(eg Airtel).
            type: str
        type: list
      services:
        description: Nfv Profile's services.
        elements: dict
        suboptions:
          firewallMode:
            description: Firewall mode details example (routed, transparent).
            type: str
          imageName:
            description: Service image name (eg isrv-universalk9.16.12.01a.tar.gz).
            type: str
          profileType:
            description: Profile type of service (eg ISRv-mini).
            type: str
          serviceName:
            description: Name of the service (eg Router-1).
            type: str
          serviceType:
            description: Service type (eg ISRV).
            type: str
          vNicMapping:
            description: Nfv Profile's vNicMapping.
            elements: dict
            suboptions:
              assignIpAddressToNetwork:
                description: Assign ip address to network (eg true or false).
                type: str
              networkType:
                description: Type of connection (eg wan, lan or internal).
                type: str
            type: list
        type: list
      vlanForL2:
        description: Nfv Profile's vlanForL2.
        elements: dict
        suboptions:
          vlanDescription:
            description: Vlan description(eg Access 4018).
            type: str
          vlanId:
            description: Vlan id (eg 4018).
            type: int
          vlanType:
            description: Vlan type(eg Access or Trunk).
            type: str
        type: list
    type: list
  id:
    description: Id path parameter. Id of the NFV profile to be updated.
    type: str
  name:
    description: Name query parameter. Name of the profile to be updated.
    type: str
  profileName:
    description: Name of the profile to create NFV profile.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Site Design CreateNFVProfile
  description: Complete reference of the CreateNFVProfile API.
  link: https://developer.cisco.com/docs/dna-center/#!create-nfv-profile
- name: Cisco DNA Center documentation for Site Design DeleteNFVProfile
  description: Complete reference of the DeleteNFVProfile API.
  link: https://developer.cisco.com/docs/dna-center/#!delete-nfv-profile
- name: Cisco DNA Center documentation for Site Design UpdateNFVProfile
  description: Complete reference of the UpdateNFVProfile API.
  link: https://developer.cisco.com/docs/dna-center/#!update-nfv-profile
notes:
  - SDK Method used are
    site_design.SiteDesign.create_nfv_profile,
    site_design.SiteDesign.delete_nfv_profile,
    site_design.SiteDesign.update_nfv_profile,

  - Paths used are
    post /dna/intent/api/v1/nfv/network-profile,
    delete /dna/intent/api/v1/nfv/network-profile/{id},
    put /dna/intent/api/v1/nfv/network-profile/{id},

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.nfv_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    device:
    - customNetworks:
      - connectionType: string
        networkName: string
        servicesToConnect:
        - serviceName: string
        vlanId: 0
        vlanMode: string
      customTemplate:
      - deviceType: string
        template: string
        templateType: string
      deviceTag: string
      deviceType: string
      directInternetAccessForFirewall: true
      serviceProviderProfile:
      - connect: true
        connectDefaultGatewayOnWan: true
        linkType: string
        serviceProvider: string
      services:
      - firewallMode: string
        imageName: string
        profileType: string
        serviceName: string
        serviceType: string
        vNicMapping:
        - assignIpAddressToNetwork: string
          networkType: string
      vlanForL2:
      - vlanDescription: string
        vlanId: 0
        vlanType: string
    profileName: string

- name: Update by id
  cisco.dnac.nfv_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    device:
    - currentDeviceTag: string
      customNetworks:
      - connectionType: string
        networkName: string
        servicesToConnect:
        - serviceName: string
        vlanId: 0
        vlanMode: string
      customTemplate:
      - deviceType: string
        template: string
        templateType: string
      deviceTag: string
      directInternetAccessForFirewall: true
      services:
      - firewallMode: string
        imageName: string
        profileType: string
        serviceName: string
        serviceType: string
        vNicMapping:
        - assignIpAddressToNetwork: string
          networkType: string
      vlanForL2:
      - vlanDescription: string
        vlanId: 0
        vlanType: string
    id: string
    name: string

- name: Delete by id
  cisco.dnac.nfv_profile:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
    name: string

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
