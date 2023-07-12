#!/usr/bin/env python

# Copyright (C) 2021  Hewlett Packard Enterprise Development LP

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# author Alok Ranjan (alok.ranjan2@hpe.com)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):

    # HPE Nimble doc fragment
    DOCUMENTATION = '''
options:
  host:
    description:
    - HPE Nimble Storage IP address.
    required: True
    type: str
  password:
    description:
    - HPE Nimble Storage password.
    required: True
    type: str
  username:
    description:
    - HPE Nimble Storage user name.
    required: True
    type: str
requirements:
  - Ansible 2.9 or later
  - Python 3.6 or later
  - HPE Nimble Storage SDK for Python
  - HPE Nimble Storage arrays running NimbleOS 5.0 or later

'''
