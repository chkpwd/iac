# -*- coding: utf-8 -*-
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options:
  name:
    description:
      - The Sensu resource's name. This name (in combination with the
        namespace where applicable) uniquely identifies the resource that
        Ansible operates on.
      - If the resource with selected name already exists, Ansible module will
        update it to match the specification in the task.
      - Consult the I(name) metadata attribute specification in the upstream
        docs on U(https://docs.sensu.io/sensu-go/latest/reference/) for
        more details about valid names and other restrictions.
    type: str
    required: yes
"""
