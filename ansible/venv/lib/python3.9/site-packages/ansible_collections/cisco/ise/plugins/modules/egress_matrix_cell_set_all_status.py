#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: egress_matrix_cell_set_all_status
short_description: Resource module for Egress Matrix Cell Set All Status
description:
- Manage operation update of the resource Egress Matrix Cell Set All Status.
- This API allows the client to set status of all the egress matrix cells.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  status:
    description: Status path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    egress_matrix_cell.EgressMatrixCell.set_all_cells_status,

  - Paths used are
    put /ers/config/egressmatrixcell/status/{status},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.egress_matrix_cell_set_all_status:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    status: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
