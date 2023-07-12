# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
  secrets:
    description:
      - List of secrets that are available to the command.
    type: list
    elements: dict
    version_added: 1.6.0
    suboptions:
      name:
        description:
          - Variable name that will contain the sensitive data.
        type: str
        required: true
        version_added: 1.6.0
      secret:
        description:
          - Name of the secret that contains sensitive data.
        type: str
        required: true
        version_added: 1.6.0
"""
