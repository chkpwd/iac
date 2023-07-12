# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Cisco and/or its affiliates.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  url:
    description: NSO JSON-RPC URL, http://localhost:8080/jsonrpc
    type: str
    required: true
  username:
    description: NSO username
    type: str
    required: true
  password:
    description: NSO password
    type: str
    required: true
  timeout:
    description: JSON-RPC request timeout in seconds
    type: int
    default: 300
  validate_certs:
    description: When set to true, validates the SSL certificate of NSO when
                 using SSL
    type: bool
    required: false
    default: false
seealso:
  - name: Cisco DevNet NSO Sandbox
    description: Provides a reservable pod with NSO, virtual network topology simulated with Cisco CML and a Linux host running Ansible
    link: https://blogs.cisco.com/developer/nso-learning-lab-and-sandbox
  - name: NSO Developer Resources on DevNet
    description: Documentation for getting started using NSO
    link: https://developer.cisco.com/docs/nso/
  - name: NSO Developer Hub
    description: Collaboration community portal for NSO developers
    link: https://community.cisco.com/t5/nso-developer-hub/ct-p/5672j-dev-nso
  - name: NSO Developer Github
    description: Code for NSO on Github
    link: https://github.com/NSO-developer/
'''
