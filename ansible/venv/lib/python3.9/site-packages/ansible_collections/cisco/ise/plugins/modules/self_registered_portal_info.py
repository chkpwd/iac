#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: self_registered_portal_info
short_description: Information module for Self Registered Portal
description:
- Get all Self Registered Portal.
- Get Self Registered Portal by id.
- This API allows the client to get a self registered portal by ID.
- This API allows the client to get all the self registered portals.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module_info
author: Rafael Campos (@racampos)
options:
  id:
    description:
    - Id path parameter.
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
seealso:
- name: Cisco ISE documentation for SelfRegisteredPortal
  description: Complete reference of the SelfRegisteredPortal API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!selfregportal
notes:
  - SDK Method used are
    self_registered_portal.SelfRegisteredPortal.get_self_registered_portal_by_id,
    self_registered_portal.SelfRegisteredPortal.get_self_registered_portals_generator,

  - Paths used are
    get /ers/config/selfregportal,
    get /ers/config/selfregportal/{id},

"""

EXAMPLES = r"""
- name: Get all Self Registered Portal
  cisco.ise.self_registered_portal_info:
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

- name: Get Self Registered Portal by id
  cisco.ise.self_registered_portal_info:
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
          "authenticationMethod": "string",
          "assignedGuestTypeForEmployee": "string",
          "displayLang": "string",
          "fallbackLanguage": "string",
          "alwaysUsedLanguage": "string"
        },
        "loginPageSettings": {
          "requireAccessCode": true,
          "maxFailedAttemptsBeforeRateLimit": 0,
          "timeBetweenLoginsDuringRateLimit": 0,
          "includeAup": true,
          "aupDisplay": "string",
          "requireAupAcceptance": true,
          "accessCode": "string",
          "allowGuestToCreateAccounts": true,
          "allowForgotPassword": true,
          "allowGuestToChangePassword": true,
          "allowAlternateGuestPortal": true,
          "alternateGuestPortal": "string",
          "allowGuestToUseSocialAccounts": true,
          "allowShowGuestForm": true,
          "socialConfigs": [
            {
              "socialMediaType": "string",
              "socialMediaValue": "string"
            }
          ]
        },
        "selfRegPageSettings": {
          "assignGuestsToGuestType": "string",
          "accountValidityDuration": 0,
          "accountValidityTimeUnits": "string",
          "requireRegistrationCode": true,
          "registrationCode": "string",
          "fieldUserName": {
            "include": true,
            "require": true
          },
          "fieldFirstName": {
            "include": true,
            "require": true
          },
          "fieldLastName": {
            "include": true,
            "require": true
          },
          "fieldEmailAddr": {
            "include": true,
            "require": true
          },
          "fieldPhoneNo": {
            "include": true,
            "require": true
          },
          "fieldCompany": {
            "include": true,
            "require": true
          },
          "fieldLocation": {
            "include": true,
            "require": true
          },
          "selectableLocations": [
            "string"
          ],
          "fieldSmsProvider": {
            "include": true,
            "require": true
          },
          "selectableSmsProviders": [
            "string"
          ],
          "fieldPersonBeingVisited": {
            "include": true,
            "require": true
          },
          "fieldReasonForVisit": {
            "include": true,
            "require": true
          },
          "includeAup": true,
          "aupDisplay": "string",
          "requireAupAcceptance": true,
          "enableGuestEmailWhitelist": true,
          "guestEmailWhitelistDomains": [
            "string"
          ],
          "enableGuestEmailBlacklist": true,
          "guestEmailBlacklistDomains": [
            "string"
          ],
          "requireGuestApproval": true,
          "autoLoginSelfWait": true,
          "autoLoginTimePeriod": 0,
          "allowGraceAccess": true,
          "graceAccessExpireInterval": 0,
          "graceAccessSendAccountExpiration": true,
          "sendApprovalRequestTo": "string",
          "approvalEmailAddresses": "string",
          "postRegistrationRedirect": "string",
          "postRegistrationRedirectUrl": "string",
          "credentialNotificationUsingEmail": true,
          "credentialNotificationUsingSms": true,
          "approveDenyLinksValidFor": 0,
          "approveDenyLinksTimeUnits": "string",
          "requireApproverToAuthenticate": true,
          "authenticateSponsorsUsingPortalList": true,
          "sponsorPortalList": [
            "string"
          ]
        },
        "selfRegSuccessSettings": {
          "includeUserName": true,
          "includePassword": true,
          "includeFirstName": true,
          "includeLastName": true,
          "includeEmailAddr": true,
          "includePhoneNo": true,
          "includeCompany": true,
          "includeLocation": true,
          "includeSmsProvider": true,
          "includePersonBeingVisited": true,
          "includeReasonForVisit": true,
          "allowGuestSendSelfUsingPrint": true,
          "allowGuestSendSelfUsingEmail": true,
          "allowGuestSendSelfUsingSms": true,
          "includeAup": true,
          "aupOnPage": true,
          "requireAupAcceptance": true,
          "requireAupScrolling": true,
          "allowGuestLoginFromSelfregSuccessPage": true
        },
        "aupSettings": {
          "includeAup": true,
          "useDiffAupForEmployees": true,
          "skipAupForEmployees": true,
          "requireScrolling": true,
          "requireAupScrolling": true,
          "displayFrequency": "string",
          "displayFrequencyIntervalDays": 0
        },
        "guestChangePasswordSettings": {
          "allowChangePasswdAtFirstLogin": true
        },
        "guestDeviceRegistrationSettings": {
          "autoRegisterGuestDevices": true,
          "allowGuestsToRegisterDevices": true
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
        "postLoginBannerSettings": {
          "includePostAccessBanner": true
        },
        "postAccessBannerSettings": {
          "includePostAccessBanner": true
        },
        "authSuccessSettings": {
          "successRedirect": "string",
          "redirectUrl": "string"
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
            "authenticationMethod": "string",
            "assignedGuestTypeForEmployee": "string",
            "displayLang": "string",
            "fallbackLanguage": "string",
            "alwaysUsedLanguage": "string"
          },
          "loginPageSettings": {
            "requireAccessCode": true,
            "maxFailedAttemptsBeforeRateLimit": 0,
            "timeBetweenLoginsDuringRateLimit": 0,
            "includeAup": true,
            "aupDisplay": "string",
            "requireAupAcceptance": true,
            "accessCode": "string",
            "allowGuestToCreateAccounts": true,
            "allowForgotPassword": true,
            "allowGuestToChangePassword": true,
            "allowAlternateGuestPortal": true,
            "alternateGuestPortal": "string",
            "allowGuestToUseSocialAccounts": true,
            "allowShowGuestForm": true,
            "socialConfigs": [
              {
                "socialMediaType": "string",
                "socialMediaValue": "string"
              }
            ]
          },
          "selfRegPageSettings": {
            "assignGuestsToGuestType": "string",
            "accountValidityDuration": 0,
            "accountValidityTimeUnits": "string",
            "requireRegistrationCode": true,
            "registrationCode": "string",
            "fieldUserName": {
              "include": true,
              "require": true
            },
            "fieldFirstName": {
              "include": true,
              "require": true
            },
            "fieldLastName": {
              "include": true,
              "require": true
            },
            "fieldEmailAddr": {
              "include": true,
              "require": true
            },
            "fieldPhoneNo": {
              "include": true,
              "require": true
            },
            "fieldCompany": {
              "include": true,
              "require": true
            },
            "fieldLocation": {
              "include": true,
              "require": true
            },
            "selectableLocations": [
              "string"
            ],
            "fieldSmsProvider": {
              "include": true,
              "require": true
            },
            "selectableSmsProviders": [
              "string"
            ],
            "fieldPersonBeingVisited": {
              "include": true,
              "require": true
            },
            "fieldReasonForVisit": {
              "include": true,
              "require": true
            },
            "includeAup": true,
            "aupDisplay": "string",
            "requireAupAcceptance": true,
            "enableGuestEmailWhitelist": true,
            "guestEmailWhitelistDomains": [
              "string"
            ],
            "enableGuestEmailBlacklist": true,
            "guestEmailBlacklistDomains": [
              "string"
            ],
            "requireGuestApproval": true,
            "autoLoginSelfWait": true,
            "autoLoginTimePeriod": 0,
            "allowGraceAccess": true,
            "graceAccessExpireInterval": 0,
            "graceAccessSendAccountExpiration": true,
            "sendApprovalRequestTo": "string",
            "approvalEmailAddresses": "string",
            "postRegistrationRedirect": "string",
            "postRegistrationRedirectUrl": "string",
            "credentialNotificationUsingEmail": true,
            "credentialNotificationUsingSms": true,
            "approveDenyLinksValidFor": 0,
            "approveDenyLinksTimeUnits": "string",
            "requireApproverToAuthenticate": true,
            "authenticateSponsorsUsingPortalList": true,
            "sponsorPortalList": [
              "string"
            ]
          },
          "selfRegSuccessSettings": {
            "includeUserName": true,
            "includePassword": true,
            "includeFirstName": true,
            "includeLastName": true,
            "includeEmailAddr": true,
            "includePhoneNo": true,
            "includeCompany": true,
            "includeLocation": true,
            "includeSmsProvider": true,
            "includePersonBeingVisited": true,
            "includeReasonForVisit": true,
            "allowGuestSendSelfUsingPrint": true,
            "allowGuestSendSelfUsingEmail": true,
            "allowGuestSendSelfUsingSms": true,
            "includeAup": true,
            "aupOnPage": true,
            "requireAupAcceptance": true,
            "requireAupScrolling": true,
            "allowGuestLoginFromSelfregSuccessPage": true
          },
          "aupSettings": {
            "includeAup": true,
            "useDiffAupForEmployees": true,
            "skipAupForEmployees": true,
            "requireScrolling": true,
            "requireAupScrolling": true,
            "displayFrequency": "string",
            "displayFrequencyIntervalDays": 0
          },
          "guestChangePasswordSettings": {
            "allowChangePasswdAtFirstLogin": true
          },
          "guestDeviceRegistrationSettings": {
            "autoRegisterGuestDevices": true,
            "allowGuestsToRegisterDevices": true
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
          "postLoginBannerSettings": {
            "includePostAccessBanner": true
          },
          "postAccessBannerSettings": {
            "includePostAccessBanner": true
          },
          "authSuccessSettings": {
            "successRedirect": "string",
            "redirectUrl": "string"
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
