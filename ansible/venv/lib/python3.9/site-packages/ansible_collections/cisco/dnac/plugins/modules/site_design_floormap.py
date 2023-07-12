#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_design_floormap
short_description: Resource module for Site Design Floormap
description:
- Manage operations create, update and delete of the resource Site Design Floormap.
- Service to create a floor map with callback.
- Service to delete an empty floor map with callback.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  floorId:
    description: FloorId path parameter. Group ID of floor to be deleted.
    type: str
  payload:
    description: Site Design Floormap's payload
    type: dict
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
notes:
  - SDK Method used are
    site_design.SiteDesign.create_floormap,
    site_design.SiteDesign.delete_floormap,
    site_design.SiteDesign.update_floormap,

  - Paths used are
    post /dna/intent/api/v1/wireless/floormap,
    delete /dna/intent/api/v1/wireless/floormap/{floorId},

"""

EXAMPLES = r"""
- name: Create
  cisco.dnac.site_design_floormap:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:

- name: Delete by id
  cisco.dnac.site_design_floormap:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    floorId: string

- name: Update by id
  cisco.dnac.site_design_floormap:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    floorId: string
    payload:

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
