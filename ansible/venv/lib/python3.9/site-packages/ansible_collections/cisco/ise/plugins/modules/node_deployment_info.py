#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: node_deployment_info
short_description: Information module for Node Deployment
description:
- Get all Node Deployment.
- Get Node Deployment by name.
- The API lists all the nodes that are deployed in the cluster.
- This API retrieves detailed information of the deployed node.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  filter:
    description:
    - >
      Filter query parameter. .. Container **Simple filtering** is available through the filter query string
      parameter. The structure of a filter is a triplet of field operator and value, separated by dots. More than
      one filter can be sent. The logical operator common to all filter criteria is AND by default, and can be
      changed by using the *"filterType=or"* query string parameter.
    - Each resource Data model description should specify if an attribute is a filtered field.
    - The 'EQ' operator describes 'Equals'.
    - The 'NEQ' operator describes 'Not Equals'.
    - The 'GT' operator describes 'Greater Than'.
    - The 'LT' operator describes 'Less Than'.
    - The 'STARTSW' operator describes 'Starts With'.
    - The 'NSTARTSW' operator describes 'Not Starts With'.
    - The 'ENDSW' operator describes 'Ends With'.
    - The 'NENDSW' operator describes 'Not Ends With'.
    - The 'CONTAINS' operator describes 'Contains'.
    - The 'NCONTAINS' operator describes 'Not Contains'.
    elements: str
    type: list
  filterType:
    description:
    - >
      FilterType query parameter. The logical operator common to all filter criteria is AND by default, and can be
      changed by using this parameter.
    type: str
  hostname:
    description:
    - Hostname path parameter. Hostname of the deployed node.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for Node Deployment
  description: Complete reference of the Node Deployment API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deployment-openapi
notes:
  - SDK Method used are
    node_deployment.NodeDeployment.get_node_details,
    node_deployment.NodeDeployment.get_nodes,

  - Paths used are
    get /api/v1/deployment/node,
    get /api/v1/deployment/node/{hostname},

"""

EXAMPLES = r"""
- name: Get all Node Deployment
  cisco.ise.node_deployment_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    filter: []
    filterType: string
  register: result

- name: Get Node Deployment by name
  cisco.ise.node_deployment_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    hostname: string
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "fqdn": "string",
      "hostname": "string",
      "ipAddress": "string",
      "nodeStatus": "string",
      "roles": [
        "string"
      ],
      "services": [
        "string"
      ]
    }
"""
