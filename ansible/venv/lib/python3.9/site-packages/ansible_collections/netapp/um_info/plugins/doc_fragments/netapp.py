# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Suhas Bangalore Shekar <bsuhas@netapp.com>
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
  - Ansible modules are available for the following NetApp Storage Management Platforms: AIQUM 9.7
'''

    # Documentation fragment for AIQUM (um)
    UM = r'''
options:
  hostname:
      description:
      - The hostname or IP address of the Unified Manager instance.
      type: str
      required: true
  username:
      description:
      - username of the Unified Manager instance.
      type: str
      required: true
  password:
      description:
      - Password for the specified user.
      type: str
      required: true
  validate_certs:
      description:
      - If set to C(False), the SSL certificates will not be validated.
      - This should only set to C(False) used on personally controlled sites using self-signed certificates.
      type: bool
      default: True
  http_port:
      description:
      - Override the default port (443) with this port
      type: int
  feature_flags:
      description:
      - Enable or disable a new feature.
      - This can be used to enable an experimental feature or disable a new feature that breaks backward compatibility.
      - Supported keys and values are subject to change without notice.  Unknown keys are ignored.
      - trace_apis can be set to true to enable tracing, data is written to /tmp/um_apis.log.
      type: dict
      version_added: 21.7.0
  max_records:
      description:
      - Maximum number of records retrieved in a single GET request.
      - This module loops on GET requests until all available records are fetched.
      - If absent, AIQUM uses 1000.
      type: int
      version_added: 21.7.0


requirements:
  - A AIQUM 9.7 system.
  - Ansible 2.9 or later.

notes:
  - With the 21.6.0 release, all modules have been renamed to na_um_<module>_info. The old ones will continue to work but will be depecrated in the future.
  - The modules prefixed with na_um are built to support the AIQUM 9.7 platform.
  - Supports check_mode.
'''
