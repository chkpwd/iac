#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: licensing_feature_to_tier_mapping_info
short_description: Information module for Licensing Feature To Tier Mapping
description:
- Get all Licensing Feature To Tier Mapping.
- Get feature to tier mapping.
version_added: '2.1.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options: {}
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Licensing
  description: Complete reference of the Licensing API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!license-openapi
notes:
  - SDK Method used are
    licensing.Licensing.get_feature_to_tier_mapping,

  - Paths used are
    get /api/v1/license/system/feature-to-tier-mapping,

"""

EXAMPLES = r"""
- name: Get all Licensing Feature To Tier Mapping
  cisco.ise.licensing_feature_to_tier_mapping_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "featureName": [
          "string"
        ],
        "tier": "string"
      }
    ]
"""
