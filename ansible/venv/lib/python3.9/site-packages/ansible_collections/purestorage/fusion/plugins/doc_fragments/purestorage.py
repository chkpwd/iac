# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Simon Dodsley <simon@purestorage.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard Pure Storage documentation fragment
    DOCUMENTATION = r"""
options:
  - See separate platform section for more details
requirements:
  - See separate platform section for more details
notes:
  - Ansible modules are available for the following Pure Storage products: FlashArray, FlashBlade, Pure1, Fusion
"""

    # Documentation fragment for Fusion
    FUSION = r"""
options:
  private_key_file:
    aliases: [ key_file ]
    description:
      - Path to the private key file
      - Defaults to the set environment variable under FUSION_PRIVATE_KEY_FILE.
    type: str
  private_key_password:
    description:
      - Password of the encrypted private key file
    type: str
  issuer_id:
    aliases: [ app_id ]
    description:
      - Application ID from Pure1 Registration page
      - eg. pure1:apikey:dssf2331sd
      - Defaults to the set environment variable under FUSION_ISSUER_ID
    type: str
  access_token:
    description:
      - Access token for Fusion Service
      - Defaults to the set environment variable under FUSION_ACCESS_TOKEN
    type: str
notes:
  - This module requires the I(purefusion) Python library
  - You must set C(FUSION_ISSUER_ID) and C(FUSION_PRIVATE_KEY_FILE) environment variables
    if I(issuer_id) and I(private_key_file) arguments are not passed to the module directly
  - If you want to use access token for authentication, you must use C(FUSION_ACCESS_TOKEN) environment variable
    if I(access_token) argument is not passed to the module directly
requirements:
  - python >= 3.8
  - purefusion
"""
