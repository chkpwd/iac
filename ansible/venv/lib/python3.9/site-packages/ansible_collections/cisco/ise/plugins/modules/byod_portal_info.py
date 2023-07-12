#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: byod_portal_info
short_description: Information module for BYOD Portal
description:
- Get all BYOD Portal.
- Get BYOD Portal by id.
- This API allows the client to get a BYOD portal by ID.
- This API allows the client to get all the BYOD portals.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter. Portal id.
    type: str
  page:
    description:
    - Page query parameter. Page number.
    type: int
  size:
    description:
    - Size query parameter. Number of objects returned per page.
    type: int
  sortasc:
    description:
    - Sortasc query parameter. Sort asc.
    type: str
  sortdsc:
    description:
    - Sortdsc query parameter. Sort desc.
    type: str
  filter:
    description:
    - >
      Filter query parameter. **Simple filtering** should be available through the filter query string parameter.
      The structure of a filter is a triplet of field operator and value separated with dots. More than one filter
      can be sent. The logical operator common to ALL filter criteria will be by default AND, and can be changed
      by using the "filterType=or" query string parameter.
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
      FilterType query parameter. The logical operator common to ALL filter criteria will be by default AND, and
      can be changed by using the parameter.
    type: str
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    byod_portal.ByodPortal.get_byod_portal_by_id,
    byod_portal.ByodPortal.get_byod_portal_generator,

  - Paths used are
    get /ers/config/byodportal,
    get /ers/config/byodportal/{id},

"""

EXAMPLES = r"""
- name: Get all BYOD Portal
  cisco.ise.byod_portal_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    page: 1
    size: 20
    sortasc: string
    sortdsc: string
    filter: []
    filterType: AND
  register: result

- name: Get BYOD Portal by id
  cisco.ise.byod_portal_info:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    id: string
  register: result

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
      "portalType": "string",
      "portalTestUrl": "string",
      "settings": {
        "portalSettings": {
          "httpsPort": 0,
          "allowedInterfaces": [
            "string"
          ],
          "certificateGroupTag": "string",
          "endpointIdentityGroup": "string",
          "displayLang": "string",
          "fallbackLanguage": "string",
          "alwaysUsedLanguage": "string"
        },
        "byodSettings": {
          "byodWelcomeSettings": {
            "enableBYOD": true,
            "enableGuestAccess": true,
            "requireMDM": true,
            "includeAup": true,
            "aupDisplay": "string",
            "requireAupAcceptance": true,
            "requireScrolling": true
          },
          "byodRegistrationSettings": {
            "showDeviceID": true,
            "endPointIdentityGroupId": "string"
          },
          "byodRegistrationSuccessSettings": {
            "successRedirect": "string",
            "redirectUrl": "string"
          }
        },
        "supportInfoSettings": {
          "includeSupportInfoPage": true,
          "includeMacAddr": true,
          "includeIpAddress": true,
          "includeBrowserUserAgent": true,
          "includePolicyServer": true,
          "includeFailureCode": true,
          "emptyFieldDisplay": "string",
          "defaultEmptyFieldValue": "string"
        }
      },
      "customizations": {
        "portalTheme": {
          "id": "string",
          "name": "string",
          "themeData": "string"
        },
        "portalTweakSettings": {
          "bannerColor": "string",
          "bannerTextColor": "string",
          "pageBackgroundColor": "string",
          "pageLabelAndTextColor": "string"
        },
        "language": {
          "viewLanguage": "string"
        },
        "globalCustomizations": {
          "mobileLogoImage": {
            "data": "string"
          },
          "desktopLogoImage": {
            "data": "string"
          },
          "bannerImage": {
            "data": "string"
          },
          "backgroundImage": {
            "data": "string"
          },
          "bannerTitle": "string",
          "contactText": "string",
          "footerElement": "string"
        },
        "pageCustomizations": {
          "data": [
            {
              "key": "string",
              "value": "string"
            }
          ]
        }
      },
      "link": {
        "rel": "string",
        "href": "string",
        "type": "string"
      }
    }

ise_responses:
  description: A dictionary or list with the response returned by the Cisco ISE Python SDK
  returned: always
  version_added: '1.1.0'
  type: list
  elements: dict
  sample: >
    [
      {
        "id": "string",
        "name": "string",
        "description": "string",
        "portalType": "string",
        "portalTestUrl": "string",
        "settings": {
          "portalSettings": {
            "httpsPort": 0,
            "allowedInterfaces": [
              "string"
            ],
            "certificateGroupTag": "string",
            "endpointIdentityGroup": "string",
            "displayLang": "string",
            "fallbackLanguage": "string",
            "alwaysUsedLanguage": "string"
          },
          "byodSettings": {
            "byodWelcomeSettings": {
              "enableBYOD": true,
              "enableGuestAccess": true,
              "requireMDM": true,
              "includeAup": true,
              "aupDisplay": "string",
              "requireAupAcceptance": true,
              "requireScrolling": true
            },
            "byodRegistrationSettings": {
              "showDeviceID": true,
              "endPointIdentityGroupId": "string"
            },
            "byodRegistrationSuccessSettings": {
              "successRedirect": "string",
              "redirectUrl": "string"
            }
          },
          "supportInfoSettings": {
            "includeSupportInfoPage": true,
            "includeMacAddr": true,
            "includeIpAddress": true,
            "includeBrowserUserAgent": true,
            "includePolicyServer": true,
            "includeFailureCode": true,
            "emptyFieldDisplay": "string",
            "defaultEmptyFieldValue": "string"
          }
        },
        "customizations": {
          "portalTheme": {
            "id": "string",
            "name": "string",
            "themeData": "string"
          },
          "portalTweakSettings": {
            "bannerColor": "string",
            "bannerTextColor": "string",
            "pageBackgroundColor": "string",
            "pageLabelAndTextColor": "string"
          },
          "language": {
            "viewLanguage": "string"
          },
          "globalCustomizations": {
            "mobileLogoImage": {
              "data": "string"
            },
            "desktopLogoImage": {
              "data": "string"
            },
            "bannerImage": {
              "data": "string"
            },
            "backgroundImage": {
              "data": "string"
            },
            "bannerTitle": "string",
            "contactText": "string",
            "footerElement": "string"
          },
          "pageCustomizations": {
            "data": [
              {
                "key": "string",
                "value": "string"
              }
            ]
          }
        },
        "link": {
          "rel": "string",
          "href": "string",
          "type": "string"
        }
      }
    ]
"""
