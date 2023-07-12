#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: external_radius_server_info
short_description: Information module for External RADIUS Server
description:
- Get all External RADIUS Server.
- Get External RADIUS Server by id.
- Get External RADIUS Server by name.
- This API allows the client to get all the external RADIUS servers.
- This API allows the client to get an external RADIUS server by ID.
- This API allows the client to get an external RADIUS server by name.
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
    external_radius_server.ExternalRadiusServer.get_external_radius_server_by_id,
    external_radius_server.ExternalRadiusServer.get_external_radius_server_by_name,
    external_radius_server.ExternalRadiusServer.get_external_radius_server_generator,

  - Paths used are
    get /ers/config/externalradiusserver,
    get /ers/config/externalradiusserver/name/{name},
    get /ers/config/externalradiusserver/{id},

"""

EXAMPLES = r"""
- name: Get all External RADIUS Server
  cisco.ise.external_radius_server_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get External RADIUS Server by id
  cisco.ise.external_radius_server_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get External RADIUS Server by name
  cisco.ise.external_radius_server_info:
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
    ]
"""
