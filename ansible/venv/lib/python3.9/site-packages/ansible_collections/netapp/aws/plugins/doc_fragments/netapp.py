# -*- coding: utf-8 -*-

# Copyright: (c) 2019, NetApp Ansible Team <ng-ansibleteam@netapp.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  - See respective platform section for more details
requirements:
  - See respective platform section for more details
notes:
  - This is documentation for NetApp's AWS CVS modules.
'''

    # Documentation fragment for AWSCVS
    AWSCVS = """
options:
  api_key:
    required: true
    type: str
    description:
    - The access key to authenticate with the AWSCVS Web Services Proxy or Embedded Web Services API.
  secret_key:
    required: true
    type: str
    description:
    - The secret_key to authenticate with the AWSCVS Web Services Proxy or Embedded Web Services API.
  api_url:
    required: true
    type: str
    description:
    - The url to the AWSCVS Web Services Proxy or Embedded Web Services API.
  validate_certs:
    required: false
    default: true
    description:
    - Should https certificates be validated?
    type: bool
  feature_flags:
      description:
      - Enable or disable a new feature.
      - This can be used to enable an experimental feature or disable a new feature that breaks backward compatibility.
      - Supported keys and values are subject to change without notice.  Unknown keys are ignored.
      - trace_apis can be set to true to enable tracing, data is written to /tmp/um_apis.log.
      type: dict
      version_added: 21.6.0
notes:
  - The modules prefixed with aws\\_cvs\\_netapp are built to Manage AWS Cloud Volumes Service .
"""
