#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: authorization_profile_info
short_description: Information module for Authorization Profile
description:
- Get all Authorization Profile.
- Get Authorization Profile by id.
- Get Authorization Profile by name.
- This API allows the client to get all authorization profiles.
- This API allows the client to get an authorization profile by ID.
- This API allows the client to get an authorization profile by name.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  name:
    description:
    - Name path parameter.
    type: str
  id:
    description:
    - Id path parameter.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    authorization_profile.AuthorizationProfile.get_authorization_profile_by_id,
    authorization_profile.AuthorizationProfile.get_authorization_profile_by_name,
    authorization_profile.AuthorizationProfile.get_authorization_profiles_generator,

  - Paths used are
    get /ers/config/authorizationprofile,
    get /ers/config/authorizationprofile/name/{name},
    get /ers/config/authorizationprofile/{id},

"""

EXAMPLES = r"""
- name: Get all Authorization Profile
  cisco.ise.authorization_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Authorization Profile by id
  cisco.ise.authorization_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Authorization Profile by name
  cisco.ise.authorization_profile_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string
  register: result

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

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
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
    ]
"""
