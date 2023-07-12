#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: tacacs_external_servers
short_description: Resource module for TACACS External Servers
description:
- Manage operations create, update and delete of the resource TACACS External Servers.
- This API creates TACACS external servers.
- This API deletes TACACS external servers.
- This API allows the client to update TACACS external servers.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  connectionPort:
    description: The port to connect the server.
    type: int
  description:
    description: TACACS External Servers's description.
    type: str
  hostIP:
    description: The server IPV4 address.
    type: str
  id:
    description: TACACS External Servers's id.
    type: str
  name:
    description: TACACS External Servers's name.
    type: str
  sharedSecret:
    description: The server shared secret.
    type: str
  singleConnect:
    description: Define the use of single connection.
    type: bool
  timeout:
    description: The server timeout.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    tacacs_external_servers.TacacsExternalServers.create_tacacs_external_servers,
    tacacs_external_servers.TacacsExternalServers.delete_tacacs_external_servers_by_id,
    tacacs_external_servers.TacacsExternalServers.update_tacacs_external_servers_by_id,

  - Paths used are
    post /ers/config/tacacsexternalservers,
    delete /ers/config/tacacsexternalservers/{id},
    put /ers/config/tacacsexternalservers/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.tacacs_external_servers:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    connectionPort: 0
    description: string
    hostIP: string
    id: string
    name: string
    sharedSecret: string
    singleConnect: true
    timeout: 0

- name: Delete by id
  cisco.ise.tacacs_external_servers:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.tacacs_external_servers:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    connectionPort: 0
    description: string
    hostIP: string
    name: string
    sharedSecret: string
    singleConnect: true
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
      "connectionPort": 0,
      "singleConnect": true,
      "sharedSecret": "string",
      "timeout": 0,
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
