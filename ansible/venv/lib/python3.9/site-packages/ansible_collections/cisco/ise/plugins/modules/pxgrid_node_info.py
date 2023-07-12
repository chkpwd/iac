#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pxgrid_node_info
short_description: Information module for pxGrid Node
description:
- Get all pxGrid Node.
- Get pxGrid Node by id.
- Get pxGrid Node by name.
- This API allows the client to get a pxGrid node by ID.
- This API allows the client to get a pxGrid node by name.
- This API allows the client to get all the npxGrid nodes.
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
    px_grid_node.PxGridNode.get_px_grid_node_by_id,
    px_grid_node.PxGridNode.get_px_grid_node_by_name,
    px_grid_node.PxGridNode.get_px_grid_node_generator,

  - Paths used are
    get /ers/config/pxgridnode,
    get /ers/config/pxgridnode/name/{name},
    get /ers/config/pxgridnode/{id},

"""

EXAMPLES = r"""
- name: Get all pxGrid Node
  cisco.ise.pxgrid_node_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
  register: result

- name: Get pxGrid Node by id
  cisco.ise.pxgrid_node_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

- name: Get pxGrid Node by name
  cisco.ise.pxgrid_node_info:
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
      "status": "string",
      "authMethod": "string",
      "groups": "string",
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
        "status": "string",
        "authMethod": "string",
        "groups": "string",
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""
