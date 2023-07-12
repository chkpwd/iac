#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: pxgrid_access_secret
short_description: Resource module for pxGrid Access Secret
description:
- Manage operation create of the resource pxGrid Access Secret.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  peerNodeName:
    description: pxGrid Access Secret's peerNodeName.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    consumer.Consumer.access_secret,

  - Paths used are
    post /control/AccessSecret,

"""

EXAMPLES = r"""
- name: Create
  cisco.ise.pxgrid_access_secret:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    peerNodeName: ise-admin-pxgrid-002

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
