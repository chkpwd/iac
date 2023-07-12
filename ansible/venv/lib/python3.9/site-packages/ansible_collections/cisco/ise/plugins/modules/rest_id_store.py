#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: rest_id_store
short_description: Resource module for REST Id Store
description:
- Manage operations create, update and delete of the resource REST Id Store.
- This API creates a REST ID store.
- This API deletes a REST ID store by name.
- This API deletes a REST ID store.
- This API allows the client to update a REST ID store by name.
- This API allows the client to update a REST ID store.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  description:
    description: REST Id Store's description.
    type: str
  ersRESTIDStoreAttributes:
    description: REST Id Store's ersRESTIDStoreAttributes.
    suboptions:
      headers:
        description: REST Id Store's headers.
        elements: dict
        suboptions:
          key:
            description: REST Id Store's key.
            type: str
          value:
            description: REST Id Store's value.
            type: str
        type: list
      predefined:
        description: The cloud provider connected to of the RESTIDStore. Options are
          - Azure, - Okta, - None.
        type: str
      rootUrl:
        description: Url of the root of the RESTIDStore.
        type: str
      usernameSuffix:
        description: Suffix of the username domain.
        type: str
    type: dict
  id:
    description: REST Id Store's id.
    type: str
  name:
    description: REST Id Store's name.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    restid_store.RestidStore.create_rest_id_store,
    restid_store.RestidStore.delete_rest_id_store_by_id,
    restid_store.RestidStore.delete_rest_id_store_by_name,
    restid_store.RestidStore.update_rest_id_store_by_id,
    restid_store.RestidStore.update_rest_id_store_by_name,

  - Paths used are
    post /ers/config/restidstore,
    delete /ers/config/restidstore/name/{name},
    delete /ers/config/restidstore/{id},
    put /ers/config/restidstore/name/{name},
    put /ers/config/restidstore/{id},

"""

EXAMPLES = r"""
- name: Update by name
  cisco.ise.rest_id_store:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    ersRestIDStoreAttributes:
      headers:
      - key: string
        value: string
      predefined: string
      rootUrl: string
      usernameSuffix: string
    id: string
    name: string

- name: Delete by name
  cisco.ise.rest_id_store:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    name: string

- name: Update by id
  cisco.ise.rest_id_store:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    ersRestIDStoreAttributes:
      headers:
      - key: string
        value: string
      predefined: string
      rootUrl: string
      usernameSuffix: string
    id: string
    name: string

- name: Delete by id
  cisco.ise.rest_id_store:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.rest_id_store:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    description: string
    ersRestIDStoreAttributes:
      headers:
      - key: string
        value: string
      predefined: string
      rootUrl: string
      usernameSuffix: string
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
      "ersRestIDStoreAttributes": {
        "usernameSuffix": "string",
        "rootUrl": "string",
        "predefined": "string",
        "headers": [
          {
            "key": "string",
            "value": "string"
          }
        ]
      },
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
