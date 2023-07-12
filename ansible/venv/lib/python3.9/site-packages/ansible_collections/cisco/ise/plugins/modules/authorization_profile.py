#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: authorization_profile
short_description: Resource module for Authorization Profile
description:
- Manage operations create, update and delete of the resource Authorization Profile.
- This API creates an authorization profile.
- This API deletes an authorization profile.
- This API allows the client to update an authorization profile.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  accessType:
    description: Allowed Values - ACCESS_ACCEPT, - ACCESS_REJECT.
    type: str
  acl:
    description: Authorization Profile's acl.
    type: str
  advancedAttributes:
    description: Authorization Profile's advancedAttributes.
    elements: dict
    suboptions:
      leftHandSideDictionaryAttribue:
        description: Authorization Profile's leftHandSideDictionaryAttribue.
        suboptions:
          AdvancedAttributeValueType:
            description: Authorization Profile's AdvancedAttributeValueType.
            type: str
          attributeName:
            description: Authorization Profile's attributeName.
            type: str
          dictionaryName:
            description: Authorization Profile's dictionaryName.
            type: str
          value:
            description: Authorization Profile's value.
            type: str
        type: dict
      rightHandSideAttribueValue:
        description: Attribute value can be of type AttributeValue or AdvancedDictionaryAttribute.
          For AttributeValue the value is String, For AdvancedDictionaryAttribute the
          value is dictionaryName and attributeName properties.
        suboptions:
          AdvancedAttributeValueType:
            description: Authorization Profile's AdvancedAttributeValueType.
            type: str
          attributeName:
            description: Authorization Profile's attributeName.
            type: str
          dictionaryName:
            description: Authorization Profile's dictionaryName.
            type: str
          value:
            description: Authorization Profile's value.
            type: str
        type: dict
    type: list
  agentlessPosture:
    description: AgentlessPosture flag.
    type: bool
  airespaceACL:
    description: Authorization Profile's airespaceACL.
    type: str
  airespaceIPv6ACL:
    description: Authorization Profile's airespaceIPv6ACL.
    type: str
  asaVpn:
    description: Authorization Profile's asaVpn.
    type: str
  authzProfileType:
    description: Allowed Values - SWITCH, - TRUSTSEC, - TACACS SWITCH is used for Standard
      Authorization Profiles.
    type: str
  autoSmartPort:
    description: Authorization Profile's autoSmartPort.
    type: str
  avcProfile:
    description: Authorization Profile's avcProfile.
    type: str
  daclName:
    description: Authorization Profile's daclName.
    type: str
  description:
    description: Authorization Profile's description.
    type: str
  easywiredSessionCandidate:
    description: EasywiredSessionCandidate flag.
    type: bool
  id:
    description: Resource UUID value.
    type: str
  interfaceTemplate:
    description: Authorization Profile's interfaceTemplate.
    type: str
  ipv6ACLFilter:
    description: Authorization Profile's ipv6ACLFilter.
    type: str
  ipv6DaclName:
    description: Authorization Profile's ipv6DaclName.
    type: str
  macSecPolicy:
    description: Allowed Values - MUST_SECURE, - MUST_NOT_SECURE, - SHOULD_SECURE.
    type: str
  name:
    description: Resource Name.
    type: str
  neat:
    description: Neat flag.
    type: bool
  profileName:
    description: Authorization Profile's profileName.
    type: str
  reauth:
    description: Authorization Profile's reauth.
    suboptions:
      connectivity:
        description: Allowed Values - DEFAULT, - RADIUS_REQUEST.
        type: str
      timer:
        description: Valid range is 1-65535.
        type: int
    type: dict
  serviceTemplate:
    description: ServiceTemplate flag.
    type: bool
  trackMovement:
    description: TrackMovement flag.
    type: bool
  vlan:
    description: Authorization Profile's vlan.
    suboptions:
      nameID:
        description: Authorization Profile's nameID.
        type: str
      tagID:
        description: Valid range is 0-31.
        type: int
    type: dict
  voiceDomainPermission:
    description: VoiceDomainPermission flag.
    type: bool
  webAuth:
    description: WebAuth flag.
    type: bool
  webRedirection:
    description: Authorization Profile's webRedirection.
    suboptions:
      WebRedirectionType:
        description: Value MUST be one of the following CentralizedWebAuth, HotSpot,
          NativeSupplicanProvisioning, ClientProvisioning. The WebRedirectionType must
          fit the portalName.
        type: str
      acl:
        description: Authorization Profile's acl.
        type: str
      displayCertificatesRenewalMessages:
        description: The displayCertificatesRenewalMessages is mandatory when 'WebRedirectionType'
          value is 'CentralizedWebAuth'. For all other 'WebRedirectionType' values the
          field must be ignored.
        type: bool
      portalName:
        description: A portal that exist in the DB and fits the WebRedirectionType.
        type: str
      staticIPHostNameFQDN:
        description: Authorization Profile's staticIPHostNameFQDN.
        type: str
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    authorization_profile.AuthorizationProfile.create_authorization_profile,
    authorization_profile.AuthorizationProfile.delete_authorization_profile_by_id,
    authorization_profile.AuthorizationProfile.update_authorization_profile_by_id,

  - Paths used are
    post /ers/config/authorizationprofile,
    delete /ers/config/authorizationprofile/{id},
    put /ers/config/authorizationprofile/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.authorization_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    accessType: string
    acl: string
    advancedAttributes:
    - leftHandSideDictionaryAttribue:
        AdvancedAttributeValueType: string
        attributeName: string
        dictionaryName: string
        value: string
      rightHandSideAttribueValue:
        AdvancedAttributeValueType: string
        attributeName: string
        dictionaryName: string
        value: string
    agentlessPosture: true
    airespaceACL: string
    airespaceIPv6ACL: string
    asaVpn: string
    authzProfileType: string
    autoSmartPort: string
    avcProfile: string
    daclName: string
    description: string
    easywiredSessionCandidate: true
    id: string
    interfaceTemplate: string
    ipv6ACLFilter: string
    ipv6DaclName: string
    macSecPolicy: string
    name: string
    neat: true
    profileName: string
    reauth:
      connectivity: string
      timer: 0
    serviceTemplate: true
    trackMovement: true
    vlan:
      nameID: string
      tagID: 0
    voiceDomainPermission: true
    webAuth: true
    webRedirection:
      WebRedirectionType: string
      acl: string
      displayCertificatesRenewalMessages: true
      portalName: string
      staticIPHostNameFQDN: string

- name: Delete by id
  cisco.ise.authorization_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.authorization_profile:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    accessType: string
    acl: string
    advancedAttributes:
    - leftHandSideDictionaryAttribue:
        AdvancedAttributeValueType: string
        attributeName: string
        dictionaryName: string
        value: string
      rightHandSideAttribueValue:
        AdvancedAttributeValueType: string
        attributeName: string
        dictionaryName: string
        value: string
    agentlessPosture: true
    airespaceACL: string
    airespaceIPv6ACL: string
    asaVpn: string
    authzProfileType: string
    autoSmartPort: string
    avcProfile: string
    daclName: string
    description: string
    easywiredSessionCandidate: true
    id: string
    interfaceTemplate: string
    ipv6ACLFilter: string
    ipv6DaclName: string
    macSecPolicy: string
    name: string
    neat: true
    profileName: string
    reauth:
      connectivity: string
      timer: 0
    serviceTemplate: true
    trackMovement: true
    vlan:
      nameID: string
      tagID: 0
    voiceDomainPermission: true
    webAuth: true
    webRedirection:
      WebRedirectionType: string
      acl: string
      displayCertificatesRenewalMessages: true
      portalName: string
      staticIPHostNameFQDN: string

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
      "advancedAttributes": [
        {
          "leftHandSideDictionaryAttribue": {
            "AdvancedAttributeValueType": "string",
            "dictionaryName": "string",
            "attributeName": "string",
            "value": "string"
          },
          "rightHandSideAttribueValue": {
            "AdvancedAttributeValueType": "string",
            "dictionaryName": "string",
            "attributeName": "string",
            "value": "string"
          }
        }
      ],
      "accessType": "string",
      "authzProfileType": "string",
      "vlan": {
        "nameID": "string",
        "tagID": 0
      },
      "reauth": {
        "timer": 0,
        "connectivity": "string"
      },
      "airespaceACL": "string",
      "airespaceIPv6ACL": "string",
      "webRedirection": {
        "WebRedirectionType": "string",
        "acl": "string",
        "portalName": "string",
        "staticIPHostNameFQDN": "string",
        "displayCertificatesRenewalMessages": true
      },
      "acl": "string",
      "trackMovement": true,
      "agentlessPosture": true,
      "serviceTemplate": true,
      "easywiredSessionCandidate": true,
      "daclName": "string",
      "voiceDomainPermission": true,
      "neat": true,
      "webAuth": true,
      "autoSmartPort": "string",
      "interfaceTemplate": "string",
      "ipv6ACLFilter": "string",
      "avcProfile": "string",
      "macSecPolicy": "string",
      "asaVpn": "string",
      "profileName": "string",
      "ipv6DaclName": "string",
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
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
