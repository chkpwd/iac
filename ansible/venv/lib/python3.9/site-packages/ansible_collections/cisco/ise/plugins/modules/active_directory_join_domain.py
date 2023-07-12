#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: active_directory_join_domain
short_description: Resource module for Active Directory Join Domain
description:
- Manage operation update of the resource Active Directory Join Domain.
- This API joins a Cisco ISE node to an Active Directory domain.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  additionalData:
    description: Active Directory Join Domain's additionalData.
    elements: dict
    suboptions:
      name:
        description: Active Directory Join Domain's name.
        type: str
      value:
        description: Active Directory Join Domain's value.
        type: str
    type: list
  id:
    description: Id path parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    active_directory.ActiveDirectory.join_domain,

  - Paths used are
    put /ers/config/activedirectory/{id}/join,

"""

EXAMPLES = r"""
- name: Update all
  cisco.ise.active_directory_join_domain:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    additionalData:
    - name: username
      value: Required. The domain user to use
    - name: password
      value: Required. The domain user's password
    - name: node
      value: Required. The name of the ISE node to join the domain. The node names can
        be retrieved with the "Node Details/Get All" ERS operation
    - name: orgunit
      value: Optional. The organizational unit in AD where the machine object for the
        joined ISE will be stored.
    id: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {}
"""
