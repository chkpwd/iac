#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: deployment_info
short_description: Information module for Deployment
description:
- Get all Deployment.
- This API allows the client to pull the deployment information.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  timeout:
    description:
    - How long to wait for the server to send data before giving up.
    type: int
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
seealso:
- name: Cisco ISE documentation for PullDeploymentInfo
  description: Complete reference of the PullDeploymentInfo API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!deploymentinfo
notes:
  - SDK Method used are
    pull_deployment_info.PullDeploymentInfo.get_deployment_info,

  - Paths used are
    get /ers/config/deploymentinfo/getAllInfo,

"""

EXAMPLES = r"""
- name: Get all Deployment
  cisco.ise.deployment_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
  register: result

"""

RETURN = r"""
ise_response:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  type: dict
  sample: >
    {
      "networkAccessInfo": {
        "deploymentID": "string",
        "isCsnEnabled": true,
        "nodeList": {
          "nodeAndScope": [
            {}
          ]
        },
        "sdaVNs": [],
        "trustSecControl": "string",
        "radius3RdParty": []
      },
      "profilerInfo": {
        "deploymentID": "string",
        "nodeList": {
          "node": [
            {
              "onlineSubscriptionEnabled": true,
              "lastAppliedFeedDateTime": "string",
              "scope": "string",
              "profiles": [
                {
                  "profile": [],
                  "customProfilesCount": 0,
                  "endpointTypes": "string",
                  "totalProfilesCount": 0,
                  "uniqueEndpointsCount": 0,
                  "unknownEndpointsCount": 0,
                  "totalEndpointsCount": 0,
                  "unknownEndpointsPercentage": 0
                }
              ]
            }
          ]
        }
      },
      "deploymentInfo": {
        "deploymentID": "string",
        "versionHistoryInfo": [
          {
            "opType": "string",
            "mainVersion": "string",
            "epochTime": 0
          }
        ],
        "nodeList": {
          "nodeAndNodeCountAndCountInfo": [
            {
              "name": "string",
              "value": {},
              "declaredType": "string",
              "scope": "string",
              "nil": true,
              "globalScope": true,
              "typeSubstituted": true
            }
          ]
        },
        "fipsstatus": "string"
      },
      "nadInfo": {
        "nodeList": {
          "nodeAndScope": [
            {}
          ]
        },
        "nadcountInfo": {
          "totalActiveNADCount": 0
        }
      },
      "mdmInfo": {
        "activeMdmServersCount": "string",
        "activeDesktopMdmServersCount": "string",
        "activeMobileMdmServersCount": "string",
        "deploymentID": "string",
        "nodeList": {
          "nodeAndScope": [
            {}
          ]
        }
      },
      "licensesInfo": {
        "deploymentID": "string",
        "nodeList": {
          "node": [
            {}
          ]
        }
      },
      "postureInfo": {
        "content": [
          {
            "name": "string",
            "value": {},
            "declaredType": "string",
            "scope": "string",
            "nil": true,
            "globalScope": true,
            "typeSubstituted": true
          }
        ]
      },
      "kongInfo": {
        "deploymentID": "string",
        "nodeList": {
          "node": [
            {
              "sn": "string",
              "service": [
                {
                  "serviceName": "string",
                  "route": [
                    {
                      "routeName": "string",
                      "httpCount": {},
                      "latencyCount": {},
                      "latencySum": {}
                    }
                  ]
                }
              ]
            }
          ]
        }
      }
    }
"""
