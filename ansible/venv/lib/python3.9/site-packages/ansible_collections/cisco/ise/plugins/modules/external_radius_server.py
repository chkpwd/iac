#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: external_radius_server
short_description: Resource module for External RADIUS Server
description:
- Manage operations create, update and delete of the resource External RADIUS Server.
- This API creates an external RADIUS server.
- This API deletes an external RADIUS server.
- This API allows the client to update an external RADIUS server.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  accountingPort:
    description: Valid Range 1 to 65535.
    type: int
  authenticationPort:
    description: Valid Range 1 to 65535.
    type: int
  authenticatorKey:
    description: The authenticatorKey is required only if enableKeyWrap is true, otherwise
      it must be ignored or empty. The maximum length is 20 ASCII characters or 40 HEXADECIMAL
      characters (depend on selection in field 'keyInputFormat').
    type: str
  description:
    description: External RADIUS Server's description.
    type: str
  enableKeyWrap:
    description: KeyWrap may only be enabled if it is supported on the device. When
      running in FIPS mode this option should be enabled for such devices.
    type: bool
  encryptionKey:
    description: The encryptionKey is required only if enableKeyWrap is true, otherwise
      it must be ignored or empty. The maximum length is 16 ASCII characters or 32 HEXADECIMAL
      characters (depend on selection in field 'keyInputFormat').
    type: str
  hostIP:
    description: The IP of the host - must be a valid IPV4 address.
    type: str
  id:
    description: External RADIUS Server's id.
    type: str
  keyInputFormat:
    description: Specifies the format of the input for fields 'encryptionKey' and 'authenticatorKey'.
      Allowed Values - ASCII - HEXADECIMAL.
    type: str
  name:
    description: Resource Name. Allowed charactera are alphanumeric and _ (underscore).
    type: str
  proxyTimeout:
    description: Valid Range 1 to 600.
    type: int
  retries:
    description: Valid Range 1 to 9.
    type: int
  sharedSecret:
    description: Shared secret maximum length is 128 characters.
    type: str
  timeout:
    description: Valid Range 1 to 120.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    external_radius_server.ExternalRadiusServer.create_external_radius_server,
    external_radius_server.ExternalRadiusServer.delete_external_radius_server_by_id,
    external_radius_server.ExternalRadiusServer.update_external_radius_server_by_id,

  - Paths used are
    post /ers/config/externalradiusserver,
    delete /ers/config/externalradiusserver/{id},
    put /ers/config/externalradiusserver/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.external_radius_server:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    accountingPort: 0
    authenticationPort: 0
    authenticatorKey: string
    description: string
    enableKeyWrap: true
    encryptionKey: string
    hostIP: string
    id: string
    keyInputFormat: string
    name: string
    proxyTimeout: 0
    retries: 0
    sharedSecret: string
    timeout: 0

- name: Delete by id
  cisco.ise.external_radius_server:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.external_radius_server:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    accountingPort: 0
    authenticationPort: 0
    authenticatorKey: string
    description: string
    enableKeyWrap: true
    encryptionKey: string
    hostIP: string
    keyInputFormat: string
    name: string
    proxyTimeout: 0
    retries: 0
    sharedSecret: string
    timeout: 0

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
      "hostIP": "string",
      "sharedSecret": "string",
      "enableKeyWrap": true,
      "encryptionKey": "string",
      "authenticatorKey": "string",
      "keyInputFormat": "string",
      "authenticationPort": 0,
      "accountingPort": 0,
      "timeout": 0,
      "retries": 0,
      "proxyTimeout": 0,
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
