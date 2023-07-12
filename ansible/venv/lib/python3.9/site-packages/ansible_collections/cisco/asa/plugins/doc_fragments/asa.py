# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function


__metaclass__ = type

# Copyright: (c) 2016, Peter Sprygada <psprygada@ansible.com>
# Copyright: (c) 2016, Patrick Ogenstad <@ogenstad>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""options:
  context:
    description:
    - Specifies which context to target if you are running in the ASA in multiple
      context mode. Defaults to the current context you login to.
    type: str
  passwords:
    description:
    - Saves running-config passwords in clear-text when set to True.
      Defaults to False
    type: bool
notes:
- For more information on using Ansible to manage network devices see the :ref:`Ansible
  Network Guide <network_guide>`
"""
