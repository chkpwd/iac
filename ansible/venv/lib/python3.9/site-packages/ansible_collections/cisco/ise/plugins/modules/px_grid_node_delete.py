#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: px_grid_node_delete
short_description: Resource module for Px Grid Node Delete
description:
- Manage operation delete of the resource Px Grid Node Delete.
- This API deletes a pxGrid node by name.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  name:
    description: Name path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    px_grid_node.PxGridNode.delete_px_grid_node_by_name,

  - Paths used are
    delete /ers/config/pxgridnode/name/{name},

"""

EXAMPLES = r"""
- name: Delete by name
  cisco.ise.px_grid_node_delete:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    name: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
