#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: downloadable_acl
short_description: Resource module for Downloadable ACL
description:
- Manage operations create, update and delete of the resource Downloadable ACL.
- This API creates a downloadable ACL.
- This API deletes a downloadable ACL.
- This API allows the client to update a downloadable ACL.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  dacl:
    description: The DACL Content. Use the string \\n for a newline.
    type: str
  daclType:
    description: Allowed values - IPV4, - IPV6, - IP_AGNOSTIC.
    type: str
  description:
    description: Use the string \\n for a newline.
    type: str
  id:
    description: Downloadable ACL's id.
    type: str
  name:
    description: Resource Name. Name may contain alphanumeric or any of the following
      characters _.-.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    downloadable_acl.DownloadableAcl.create_downloadable_acl,
    downloadable_acl.DownloadableAcl.delete_downloadable_acl_by_id,
    downloadable_acl.DownloadableAcl.update_downloadable_acl_by_id,

  - Paths used are
    post /ers/config/downloadableacl,
    delete /ers/config/downloadableacl/{id},
    put /ers/config/downloadableacl/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.downloadable_acl:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    dacl: string
    daclType: string
    description: string
    id: string
    name: string

- name: Update by id with multiline ACL
  cisco.ise.downloadable_acl:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    dacl: "permit udp any eq bootpc any eq bootps\n permit tcp any host {{ise-ip}} eq www"
    daclType: string
    description: "this is my\n multiline\n ACL."
    id: string
    name: string

- name: Delete by id
  cisco.ise.downloadable_acl:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.downloadable_acl:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    dacl: string
    daclType: string
    description: string
    name: string

- name: Create with multiline ACL
  cisco.ise.downloadable_acl:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    dacl: "permit udp any eq bootpc any eq bootps\n permit tcp any host {{ise-ip}} eq www"
    daclType: string
    description: "this is my\n multiline\n ACL."
    name: string

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "name": "string",
      "description": "string",
      "dacl": "string",
      "daclType": "string",
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_update_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: dict
  sample: >
    {
      "UpdatedFieldsList": {
        "updatedField": [
          {
            "field": "string",
            "oldValue": "string",
            "newValue": "string"
          }
        ],
        "field": "string",
        "oldValue": "string",
        "newValue": "string"
      }
    }
"""
