#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: endpoint_group
short_description: Resource module for Endpoint Group
description:
- Manage operations create, update and delete of the resource Endpoint Group.
- This API creates an endpoint identity group.
- This API deletes an endpoint identity group.
- This API allows the client to update an endpoint identity group.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: Endpoint Group's description.
    type: str
  id:
    description: Endpoint Group's id.
    type: str
  name:
    description: Endpoint Group's name.
    type: str
  systemDefined:
    description: SystemDefined flag.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for EndpointIdentityGroup
  description: Complete reference of the EndpointIdentityGroup API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!endpointgroup
notes:
  - SDK Method used are
    endpoint_identity_group.EndpointIdentityGroup.create_endpoint_group,
    endpoint_identity_group.EndpointIdentityGroup.delete_endpoint_group_by_id,
    endpoint_identity_group.EndpointIdentityGroup.update_endpoint_group_by_id,

  - Paths used are
    post /ers/config/endpointgroup,
    delete /ers/config/endpointgroup/{id},
    put /ers/config/endpointgroup/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.endpoint_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    id: string
    name: string
    systemDefined: true

- name: Delete by id
  cisco.ise.endpoint_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.endpoint_group:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    name: string
    systemDefined: true

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
      "systemDefined": true,
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
