#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sg_mapping_deploy
short_description: Resource module for SG Mapping Deploy
description:
- Manage operation update of the resource SG Mapping Deploy.
- This API allows the client to deploy an IP to SGT mapping by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for IPToSGTMapping
  description: Complete reference of the IPToSGTMapping API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!sgmapping
notes:
  - SDK Method used are
    ip_to_sgt_mapping.IpToSgtMapping.deploy_ip_to_sgt_mapping_by_id,

  - Paths used are
    put /ers/config/sgmapping/{id}/deploy,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.sg_mapping_deploy:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
