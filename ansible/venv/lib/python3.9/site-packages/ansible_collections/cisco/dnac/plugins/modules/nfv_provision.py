#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: nfv_provision
short_description: Resource module for Nfv Provision
description:
- Manage operation create of the resource Nfv Provision.
- Design and Provision single/multi NFV device with given site/area/building/floor .
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  provisioning:
    description: Nfv Provision's provisioning.
    elements: dict
    suboptions:
      device:
        description: Nfv Provision's device.
        elements: dict
        suboptions:
          customNetworks:
            description: Nfv Provision's customNetworks.
            elements: dict
            suboptions:
              ipAddressPool:
                description: IP address pool of sub pool (eg 175.175.140.1).
                type: str
              name:
                description: Name of custom network (eg cust-1).
                type: str
              port:
                description: Port for custom network (eg 443).
                type: str
            type: list
          deviceSerialNumber:
            description: Serial number of device (eg FGL210710QY).
            type: str
          ip:
            description: IP address of the device (eg 172.20.126.90).
            type: str
          serviceProviders:
            description: Nfv Provision's serviceProviders.
            elements: dict
            suboptions:
              serviceProvider:
                description: Name of the service provider (eg Airtel).
                type: str
              wanInterface:
                description: Nfv Provision's wanInterface.
                suboptions:
                  bandwidth:
                    description: Bandwidth limit (eg 100).
                    type: str
                  gateway:
                    description: Gateway (eg 175.175.190.1).
                    type: str
                  interfaceName:
                    description: Name of the interface (eg GE0-0).
                    type: str
                  ipAddress:
                    description: IP address (eg 175.175.190.205).
                    type: str
                  subnetmask:
                    description: Subnet mask (eg 255.255.255.0).
                    type: str
                type: dict
            type: list
          services:
            description: Nfv Provision's services.
            elements: dict
            suboptions:
              adminPasswordHash:
                description: Admin password hash.
                type: str
              centralManagerIP:
                description: WAAS Package needs to be installed to populate Central
                  Manager IP automatically.
                type: str
              centralRegistrationKey:
                description: Central registration key.
                type: str
              commonKey:
                description: Common key.
                type: str
              disk:
                description: Name of disk type (eg internal).
                type: str
              mode:
                description: Mode of firewall (eg transparent).
                type: str
              systemIp:
                description: System IP.
                type: str
              type:
                description: Type of service (eg ISR).
                type: str
            type: list
          subPools:
            description: Nfv Provision's subPools.
            elements: dict
            suboptions:
              gateway:
                description: IP address for gate way (eg 175.175.140.1).
                type: str
              ipSubnet:
                description: IP pool cidir (eg 175.175.140.0).
                type: str
              name:
                description: Name of the ip sub pool (eg; Lan-65).
                type: str
              parentPoolName:
                description: Name of parent pool (global pool name).
                type: str
              type:
                description: Tyep of ip sub pool (eg Lan).
                type: str
            type: list
          tagName:
            description: Name of device tag (eg dev1).
            type: str
          templateParam:
            description: Nfv Provision's templateParam.
            suboptions:
              asav:
                description: Nfv Provision's asav.
                suboptions:
                  var1:
                    description: Variable for asav template (eg "test" "Hello asav").
                    type: str
                type: dict
              nfvis:
                description: Nfv Provision's nfvis.
                suboptions:
                  var1:
                    description: Variable for nfvis template (eg "test" "Hello nfvis").
                    type: str
                type: dict
            type: dict
          vlan:
            description: Nfv Provision's vlan.
            elements: dict
            suboptions:
              id:
                description: Vlan id(e .4018).
                type: str
              interfaces:
                description: Interface (eg GigabitEathernet1/0).
                type: str
              network:
                description: Network name to connect (eg lan-net).
                type: str
              type:
                description: Vlan type(eg. Access or Trunk).
                type: str
            type: list
        type: list
      site:
        description: Nfv Provision's site.
        suboptions:
          area:
            description: Nfv Provision's area.
            suboptions:
              name:
                description: Name of the area (eg Area1).
                type: str
              parentName:
                description: Parent name of the area to be created.
                type: str
            type: dict
          building:
            description: Nfv Provision's building.
            suboptions:
              address:
                description: Address of the building to be created.
                type: str
              latitude:
                description: Latitude coordinate of the building (eg 37.338).
                type: int
              longitude:
                description: Longitude coordinate of the building (eg -121.832).
                type: int
              name:
                description: Name of the building (eg building1).
                type: str
              parentName:
                description: Address of the building to be created.
                type: str
            type: dict
          floor:
            description: Nfv Provision's floor.
            suboptions:
              height:
                description: Height of the floor (eg 15).
                type: int
              length:
                description: Length of the floor (eg 100).
                type: int
              name:
                description: Name of the floor (eg floor-1).
                type: str
              parentName:
                description: Parent name of the floor to be created.
                type: str
              rfModel:
                description: Type of floor (eg Cubes And Walled Offices).
                type: str
              width:
                description: Width of the floor (eg 100).
                type: int
            type: dict
          siteProfileName:
            description: Name of site profile to be provision with device.
            type: str
        type: dict
    type: list
  siteProfile:
    description: Nfv Provision's siteProfile.
    elements: dict
    suboptions:
      device:
        description: Nfv Provision's device.
        elements: dict
        suboptions:
          customNetworks:
            description: Nfv Provision's customNetworks.
            elements: dict
            suboptions:
              connectionType:
                description: Type of network connection from custom network (eg lan).
                type: str
              name:
                description: Name of custom network (eg cust-1).
                type: str
              networkMode:
                description: Network mode (eg Access or Trunk).
                type: str
              servicesToConnect:
                description: Nfv Provision's servicesToConnect.
                elements: dict
                suboptions:
                  service:
                    description: Name of service to be connected to the custom network
                      (eg router-1).
                    type: str
                type: list
              vlan:
                description: Vlan id for the custom network(eg 4000).
                type: str
            type: list
          customServices:
            description: Nfv Provision's customServices.
            elements: dict
            suboptions:
              applicationType:
                description: Application type of custom service (eg LINUX).
                type: str
              imageName:
                description: Image name of custom service (eg redhat7.tar.gz.tar.gz).
                type: str
              name:
                description: Name of custom service (eg LINUX-1).
                type: str
              profile:
                description: Profile type of service (eg rhel7-medium).
                type: str
              topology:
                description: Nfv Provision's topology.
                suboptions:
                  assignIp:
                    description: Assign ip to network (eg true).
                    type: str
                  name:
                    description: Name of connection from custom service(eg wan-net).
                    type: str
                  type:
                    description: Type of connection from custom service (eg wan, lan
                      or internal).
                    type: str
                type: dict
            type: list
          customTemplate:
            description: Nfv Provision's customTemplate.
            elements: dict
            suboptions:
              deviceType:
                description: Type of the device(eg NFVIS).
                type: str
              template:
                description: Name of the template(eg NFVIS template).
                type: str
            type: list
          deviceType:
            description: Name of the device used in creating nfv profile(eg ENCS5400).
            type: str
          dia:
            description: Direct internet access value should be boolean (eg false).
            type: bool
          serviceProviders:
            description: Nfv Provision's serviceProviders.
            elements: dict
            suboptions:
              connect:
                description: Connection of service provider and device value should
                  be boolean (eg true).
                type: bool
              defaultGateway:
                description: Default gateway connect value as boolean (eg true).
                type: bool
              linkType:
                description: Name of connection type(eg GigabitEthernet).
                type: str
              serviceProvider:
                description: Name of the service provider(eg Airtel).
                type: str
            type: list
          services:
            description: Nfv Provision's services.
            elements: dict
            suboptions:
              imageName:
                description: Name of image (eg isrv-universalk9.16.06.02.tar.gz).
                type: str
              mode:
                description: Mode of firewall (eg routed, transparent).
                type: str
              name:
                description: Name of the service (eg isrv).
                type: str
              profile:
                description: Profile type of service (eg ISRv-mini).
                type: str
              topology:
                description: Nfv Provision's topology.
                suboptions:
                  assignIp:
                    description: Assign ip address to network (eg true).
                    type: str
                  name:
                    description: Name of connection (eg wan-net).
                    type: str
                  type:
                    description: Type of connection (eg wan, lan or internal).
                    type: str
                type: dict
              type:
                description: Service type (eg ISRV).
                type: str
            type: list
          tagName:
            description: Device Tag name(eg dev1).
            type: str
          vlan:
            description: Nfv Provision's vlan.
            elements: dict
            suboptions:
              id:
                description: Vlan id(eg.4018).
                type: str
              type:
                description: Vlan type(eg. Access or Trunk).
                type: str
            type: list
        type: list
      siteProfileName:
        description: Name of the profile to create site profile profile( eg profile-1).
        type: str
    type: list
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
seealso:
- name: Cisco DNA Center documentation for Site Design ProvisionNFV
  description: Complete reference of the ProvisionNFV API.
  link: https://developer.cisco.com/docs/dna-center/#!provision-nfv
notes:
  - SDK Method used are
    site_design.SiteDesign.provision_nfv,

  - Paths used are
    post /dna/intent/api/v1/business/nfv,

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.nfv_provision:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    provisioning:
    - device:
      - customNetworks:
        - ipAddressPool: string
          name: string
          port: string
        deviceSerialNumber: string
        ip: string
        serviceProviders:
        - serviceProvider: string
          wanInterface:
            bandwidth: string
            gateway: string
            interfaceName: string
            ipAddress: string
            subnetmask: string
        services:
        - adminPasswordHash: string
          centralManagerIP: string
          centralRegistrationKey: string
          commonKey: string
          disk: string
          mode: string
          systemIp: string
          type: string
        subPools:
        - gateway: string
          ipSubnet: string
          name: string
          parentPoolName: string
          type: string
        tagName: string
        templateParam:
          asav:
            var1: string
          nfvis:
            var1: string
        vlan:
        - id: string
          interfaces: string
          network: string
          type: string
      site:
        area:
          name: string
          parentName: string
        building:
          address: string
          latitude: 0
          longitude: 0
          name: string
          parentName: string
        floor:
          height: 0
          length: 0
          name: string
          parentName: string
          rfModel: string
          width: 0
        siteProfileName: string
    siteProfile:
    - device:
      - customNetworks:
        - connectionType: string
          name: string
          networkMode: string
          servicesToConnect:
          - service: string
          vlan: string
        customServices:
        - applicationType: string
          imageName: string
          name: string
          profile: string
          topology:
            assignIp: string
            name: string
            type: string
        customTemplate:
        - deviceType: string
          template: string
        deviceType: string
        dia: true
        serviceProviders:
        - connect: true
          defaultGateway: true
          linkType: string
          serviceProvider: string
        services:
        - imageName: string
          mode: string
          name: string
          profile: string
          topology:
            assignIp: string
            name: string
            type: string
          type: string
        tagName: string
        vlan:
        - id: string
          type: string
      siteProfileName: string

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
