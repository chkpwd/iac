#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_design_floormap_info
short_description: Information module for Site Design Floormap
description:
- Get all Site Design Floormap.
- Get Site Design Floormap by id.
- List all floor maps.
- List specified floor map(s).
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  floorId:
    description:
    - FloorId path parameter. Group Id of the specified floormap.
    type: str
requirements:
- dnacentersdk >= 2.5.5
- python >= 3.5
notes:
  - SDK Method used are
    site_design.SiteDesign.get_floormap,
    site_design.SiteDesign.get_floormaps,

  - Paths used are
    get /dna/intent/api/v1/wireless/floormap/all,
    get /dna/intent/api/v1/wireless/floormap/{floorId},

"""

EXAMPLES = r"""
- name: Get all Site Design Floormap
  cisco.dnac.site_design_floormap_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
  register: result

- name: Get Site Design Floormap by id
  cisco.dnac.site_design_floormap_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers:
      custom: value
    floorId: string
  register: result

"""

RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample:
  - {}
"""
