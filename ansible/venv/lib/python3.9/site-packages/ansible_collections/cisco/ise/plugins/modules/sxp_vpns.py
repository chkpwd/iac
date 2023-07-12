#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sxp_vpns
short_description: Resource module for SXP VPNs
description:
- Manage operations create and delete of the resource SXP VPNs.
- This API creates a SXP VPN.
- This API deletes a SXP VPN.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter.
    type: str
  sxpVpnName:
    description: SXP VPNs's sxpVpnName.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    sxp_vpns.SxpVpns.create_sxp_vpn,
    sxp_vpns.SxpVpns.delete_sxp_vpn_by_id,

  - Paths used are
    post /ers/config/sxpvpns,
    delete /ers/config/sxpvpns/{id},

"""

EXAMPLES = r"""
- name: Delete by id
  cisco.ise.sxp_vpns:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sxp_vpns:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    sxpVpnName: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "sxpVpnName": "string",
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }
"""
