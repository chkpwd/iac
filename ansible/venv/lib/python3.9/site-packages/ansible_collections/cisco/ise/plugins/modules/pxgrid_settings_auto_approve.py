#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pxgrid_settings_auto_approve
short_description: Resource module for pxGrid Settings Auto Approve
description:
- Manage operation update of the resource pxGrid Settings Auto Approve.
- This API allows the client to auto approve the pxGrid settings.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  allowPasswordBasedAccounts:
    description: Allow password based accounts when true.
    type: bool
  autoApproveCertBasedAccounts:
    description: Auto approve certificate based accounts when true.
    type: bool
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    px_grid_settings.PxGridSettings.autoapprove_px_grid_settings,

  - Paths used are
    put /ers/config/pxgridsettings/autoapprove,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.pxgrid_settings_auto_approve:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    allowPasswordBasedAccounts: true
    autoApproveCertBasedAccounts: true

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
