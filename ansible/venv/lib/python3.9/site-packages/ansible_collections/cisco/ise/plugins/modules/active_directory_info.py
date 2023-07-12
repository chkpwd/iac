#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: active_directory_info
short_description: Information module for Active Directory
description:
- Get all Active Directory.
- Get Active Directory by id.
- Get Active Directory by name.
- This API allows the client to get Active Directory by name.
- This API fetchs the join point details by ID. The ID can be retrieved with the.
- This API lists all the join points for Active Directory domains in Cisco ISE.
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
    active_directory.ActiveDirectory.get_active_directory_by_id,
    active_directory.ActiveDirectory.get_active_directory_by_name,
    active_directory.ActiveDirectory.get_active_directory_generator,

  - Paths used are
    get /ers/config/activedirectory,
    get /ers/config/activedirectory/name/{name},
    get /ers/config/activedirectory/{id},

"""

EXAMPLES = r"""
- name: Get all Active Directory
  cisco.ise.active_directory_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Active Directory by id
  cisco.ise.active_directory_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Active Directory by name
  cisco.ise.active_directory_info:
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
      "domain": "string",
      "enableDomainWhiteList": true,
      "enableDomainAllowedList": true,
      "adgroups": {
        "groups": [
          {
            "name": "string",
            "sid": "string",
            "type": "string"
          }
        ]
      },
      "advancedSettings": {
        "enablePassChange": true,
        "enableMachineAuth": true,
        "enableMachineAccess": true,
        "agingTime": 0,
        "enableDialinPermissionCheck": true,
        "enableCallbackForDialinClient": true,
        "plaintextAuth": true,
        "enableFailedAuthProtection": true,
        "authProtectionType": "string",
        "failedAuthThreshold": 0,
        "identityNotInAdBehaviour": "string",
        "unreachableDomainsBehaviour": "string",
        "enableRewrites": true,
        "rewriteRules": [
          {
            "rowId": 0,
            "rewriteMatch": "string",
            "rewriteResult": "string"
          }
        ],
        "firstName": "string",
        "department": "string",
        "lastName": "string",
        "organizationalUnit": "string",
        "jobTitle": "string",
        "locality": "string",
        "email": "string",
        "stateOrProvince": "string",
        "telephone": "string",
        "country": "string",
        "streetAddress": "string",
        "schema": "string"
      },
      "adAttributes": {
        "attributes": [
          {
            "name": "string",
            "type": "string",
            "internalName": "string",
            "defaultValue": "string"
          }
        ]
      },
      "adScopesNames": "string",
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
        "domain": "string",
        "enableDomainWhiteList": true,
        "enableDomainAllowedList": true,
        "adgroups": {
          "groups": [
            {
              "name": "string",
              "sid": "string",
              "type": "string"
            }
          ]
        },
        "advancedSettings": {
          "enablePassChange": true,
          "enableMachineAuth": true,
          "enableMachineAccess": true,
          "agingTime": 0,
          "enableDialinPermissionCheck": true,
          "enableCallbackForDialinClient": true,
          "plaintextAuth": true,
          "enableFailedAuthProtection": true,
          "authProtectionType": "string",
          "failedAuthThreshold": 0,
          "identityNotInAdBehaviour": "string",
          "unreachableDomainsBehaviour": "string",
          "enableRewrites": true,
          "rewriteRules": [
            {
              "rowId": 0,
              "rewriteMatch": "string",
              "rewriteResult": "string"
            }
          ],
          "firstName": "string",
          "department": "string",
          "lastName": "string",
          "organizationalUnit": "string",
          "jobTitle": "string",
          "locality": "string",
          "email": "string",
          "stateOrProvince": "string",
          "telephone": "string",
          "country": "string",
          "streetAddress": "string",
          "schema": "string"
        },
        "adAttributes": {
          "attributes": [
            {
              "name": "string",
              "type": "string",
              "internalName": "string",
              "defaultValue": "string"
            }
          ]
        },
        "adScopesNames": "string",
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""
