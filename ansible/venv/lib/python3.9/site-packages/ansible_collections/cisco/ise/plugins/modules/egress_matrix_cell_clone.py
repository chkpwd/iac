#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: egress_matrix_cell_clone
short_description: Resource module for Egress Matrix Cell Clone
description:
- Manage operation update of the resource Egress Matrix Cell Clone.
- This API allows the client to clone an egress matrix cell.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  dstSGtId:
    description: DstSGtId path parameter.
    type: str
  id:
    description: Id path parameter.
    type: str
  srcSGtId:
    description: SrcSGtId path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    egress_matrix_cell.EgressMatrixCell.clone_matrix_cell,

  - Paths used are
    put /ers/config/egressmatrixcell/clonecell/{id}/srcSgt/{srcSgtId}/dstSgt/{dstSgtId},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.egress_matrix_cell_clone:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    dstSgtId: string
    id: string
    srcSgtId: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "OperationResult": {
        "resultValue": [
          {
            "value": "string",
            "name": "string"
          }
        ]
      }
    }
"""
