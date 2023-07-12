#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: session_service_node_info
short_description: Information module for Session Service Node
description:
- Get all Session Service Node.
- Get Session Service Node by id.
- Get Session Service Node by name.
- This API allows the client to get a PSN node details by ID.
- This API allows the client to get a PSN node details by name.
- This API allows the client to get all the PSN node details.
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
seealso:
- name: Cisco ISE documentation for PsnNodeDetailsWithRadiusService
  description: Complete reference of the PsnNodeDetailsWithRadiusService API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sessionservicenode
notes:
  - SDK Method used are
    psn_node_details_with_radius_service.PsnNodeDetailsWithRadiusService.get_session_service_node_by_id,
    psn_node_details_with_radius_service.PsnNodeDetailsWithRadiusService.get_session_service_node_by_name,
    psn_node_details_with_radius_service.PsnNodeDetailsWithRadiusService.get_session_service_node_generator,

  - Paths used are
    get /ers/config/sessionservicenode,
    get /ers/config/sessionservicenode/name/{name},
    get /ers/config/sessionservicenode/{id},

"""

EXAMPLES = r"""
- name: Get all Session Service Node
  cisco.ise.session_service_node_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get Session Service Node by id
  cisco.ise.session_service_node_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get Session Service Node by name
  cisco.ise.session_service_node_info:
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
      "ipAddress": "string",
      "gateWay": "string",
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
        "ipAddress": "string",
        "gateWay": "string",
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""
