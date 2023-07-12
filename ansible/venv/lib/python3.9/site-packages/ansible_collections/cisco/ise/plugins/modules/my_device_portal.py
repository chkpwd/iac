#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: my_device_portal
short_description: Resource module for My Device Portal
description:
- Manage operations create, update and delete of the resource My Device Portal.
- This API creates a my device portal.
- This API deletes a my device portal by ID.
- This API allows the client to update a my device portal by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  customizations:
    description: Defines all of the Portal Customizations available.
    suboptions:
      globalCustomizations:
        description: My Device Portal's globalCustomizations.
        suboptions:
          backgroundImage:
            description: My Device Portal's backgroundImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerImage:
            description: My Device Portal's bannerImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerTitle:
            description: My Device Portal's bannerTitle.
            type: str
          contactText:
            description: My Device Portal's contactText.
            type: str
          desktopLogoImage:
            description: My Device Portal's desktopLogoImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          footerElement:
            description: My Device Portal's footerElement.
            type: str
          mobileLogoImage:
            description: My Device Portal's mobileLogoImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
        type: dict
      language:
        description: This property is supported only for Read operation and it allows
          to show the customizations in English. Other languages are not supported.
        suboptions:
          viewLanguage:
            description: My Device Portal's viewLanguage.
            type: str
        type: dict
      pageCustomizations:
        description: Represent the entire page customization as a giant dictionary.
        suboptions:
          data:
            description: The Dictionary will be exposed here as key value pair.
            elements: dict
            suboptions:
              key:
                description: My Device Portal's key.
                type: str
              value:
                description: My Device Portal's value.
                type: str
            type: list
        type: dict
      portalTheme:
        description: My Device Portal's portalTheme.
        suboptions:
          id:
            description: My Device Portal's id.
            type: str
          name:
            description: The system- or user-assigned name of the portal theme.
            type: str
          themeData:
            description: A CSS file, represented as a Base64-encoded byte array.
            type: str
        type: dict
      portalTweakSettings:
        description: The Tweak Settings are a customization of the Portal Theme that
          has been selected for the portal. When the Portal Theme selection is changed,
          the Tweak Settings are overwritten to match the values in the theme. The Tweak
          Settings can subsequently be changed by the user.
        suboptions:
          bannerColor:
            description: Hex value of color.
            type: str
          bannerTextColor:
            description: My Device Portal's bannerTextColor.
            type: str
          pageBackgroundColor:
            description: My Device Portal's pageBackgroundColor.
            type: str
          pageLabelAndTextColor:
            description: My Device Portal's pageLabelAndTextColor.
            type: str
        type: dict
    type: dict
  description:
    description: My Device Portal's description.
    type: str
  id:
    description: My Device Portal's id.
    type: str
  name:
    description: My Device Portal's name.
    type: str
  portalTestUrl:
    description: URL to bring up a test page for this portal.
    type: str
  portalType:
    description: Allowed values - BYOD, - HOTSPOTGUEST, - MYDEVICE, - SELFREGGUEST,
      - SPONSOR, - SPONSOREDGUEST.
    type: str
  settings:
    description: Defines all of the settings groups available for a Mydevice portal.
    suboptions:
      aupSettings:
        description: Configuration of the Acceptable Use Policy (AUP) for a portal.
        suboptions:
          displayFrequency:
            description: How the AUP should be displayed, either on page or as a link.
              Only valid if includeAup = true. Allowed Values - FIRSTLOGIN, - EVERYLOGIN,
              - RECURRING.
            type: str
          displayFrequencyIntervalDays:
            description: Number of days between AUP confirmations (when displayFrequency
              = recurring).
            type: int
          includeAup:
            description: Require the portal user to read and accept an AUP.
            type: bool
          requireScrolling:
            description: Require the portal user to scroll to the end of the AUP. Only
              valid if requireAupAcceptance = true.
            type: bool
        type: dict
      employeeChangePasswordSettings:
        description: My Device Portal's employeeChangePasswordSettings.
        suboptions:
          allowEmployeeToChangePwd:
            description: AllowEmployeeToChangePwd flag.
            type: bool
        type: dict
      loginPageSettings:
        description: My Device Portal's loginPageSettings.
        suboptions:
          aupDisplay:
            description: How the AUP should be displayed, either on page or as a link.
              Only valid if includeAup = true. Allowed values - ONPAGE, - ASLINK.
            type: str
          includeAup:
            description: Include an Acceptable Use Policy (AUP) that should be displayed
              during login.
            type: bool
          maxFailedAttemptsBeforeRateLimit:
            description: Maximum failed login attempts before rate limiting.
            type: int
          requireAupAcceptance:
            description: Require the portal user to accept the AUP. Only valid if includeAup
              = true.
            type: bool
          requireScrolling:
            description: Require the portal user to scroll to the end of the AUP. Only
              valid if requireAupAcceptance = true.
            type: bool
          socialConfigs:
            description: My Device Portal's socialConfigs.
            elements: dict
            type: list
          timeBetweenLoginsDuringRateLimit:
            description: Time between login attempts when rate limiting.
            type: int
        type: dict
      portalSettings:
        description: The port, interface, certificate, and other basic settings of a
          portal.
        suboptions:
          allowedInterfaces:
            description: Interfaces that the portal will be reachable on. Allowed values
              - eth0, - eth1, - eth2, - eth3, - eth4, - eth5, - bond0, - bond1, - bond2.
            elements: str
            type: list
          alwaysUsedLanguage:
            description: My Device Portal's alwaysUsedLanguage.
            type: str
          certificateGroupTag:
            description: Logical name of the x.509 server certificate that will be used
              for the portal.
            type: str
          displayLang:
            description: Allowed values - USEBROWSERLOCALE, - ALWAYSUSE.
            type: str
          endpointIdentityGroup:
            description: Unique Id of the endpoint identity group where user's devices
              will be added. Used only in Hotspot Portal.
            type: str
          fallbackLanguage:
            description: Used when displayLang = USEBROWSERLOCALE.
            type: str
          httpsPort:
            description: The port number that the allowed interfaces will listen on.
              Range from 8000 to 8999.
            type: int
        type: dict
      postAccessBannerSettings:
        description: My Device Portal's postAccessBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: IncludePostAccessBanner flag.
            type: bool
        type: dict
      postLoginBannerSettings:
        description: My Device Portal's postLoginBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: Include a Post-Login Banner page.
            type: bool
        type: dict
      supportInfoSettings:
        description: My Device Portal's supportInfoSettings.
        suboptions:
          defaultEmptyFieldValue:
            description: The default value displayed for an empty field. Only valid
              when emptyFieldDisplay = DISPLAYWITHDEFAULTVALUE.
            type: str
          emptyFieldDisplay:
            description: Specifies how empty fields are handled on the Support Information
              Page. Allowed values - HIDE, - DISPLAYWITHNOVALUE, - DISPLAYWITHDEFAULTVALUE.
            type: str
          includeBrowserUserAgent:
            description: IncludeBrowserUserAgent flag.
            type: bool
          includeFailureCode:
            description: IncludeFailureCode flag.
            type: bool
          includeIpAddress:
            description: IncludeIpAddress flag.
            type: bool
          includeMacAddr:
            description: IncludeMacAddr flag.
            type: bool
          includePolicyServer:
            description: IncludePolicyServer flag.
            type: bool
          includeSupportInfoPage:
            description: IncludeSupportInfoPage flag.
            type: bool
        type: dict
    type: dict
requirements:
- ciscoisesdk >= 2.0.8
- python >= 3.5
notes:
  - SDK Method used are
    my_device_portal.MyDevicePortal.create_my_device_portal,
    my_device_portal.MyDevicePortal.delete_my_device_portal_by_id,
    my_device_portal.MyDevicePortal.update_my_device_portal_by_id,

  - Paths used are
    post /ers/config/mydeviceportal,
    delete /ers/config/mydeviceportal/{id},
    put /ers/config/mydeviceportal/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.my_device_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    customizations:
      globalCustomizations:
        backgroundImage:
          data: string
        bannerImage:
          data: string
        bannerTitle: string
        contactText: string
        desktopLogoImage:
          data: string
        footerElement: string
        mobileLogoImage:
          data: string
      language:
        viewLanguage: string
      pageCustomizations:
        data:
        - key: string
          value: string
      portalTheme:
        id: string
        name: string
        themeData: string
      portalTweakSettings:
        bannerColor: string
        bannerTextColor: string
        pageBackgroundColor: string
        pageLabelAndTextColor: string
    description: string
    id: string
    name: string
    portalTestUrl: string
    portalType: string
    settings:
      aupSettings:
        displayFrequency: string
        displayFrequencyIntervalDays: 0
        includeAup: true
        requireScrolling: true
      employeeChangePasswordSettings:
        allowEmployeeToChangePwd: true
      loginPageSettings:
        aupDisplay: string
        includeAup: true
        maxFailedAttemptsBeforeRateLimit: 0
        requireAupAcceptance: true
        requireScrolling: true
        socialConfigs:
        - {}
        timeBetweenLoginsDuringRateLimit: 0
      portalSettings:
        allowedInterfaces:
        - string
        alwaysUsedLanguage: string
        certificateGroupTag: string
        displayLang: string
        endpointIdentityGroup: string
        fallbackLanguage: string
        httpsPort: 0
      postAccessBannerSettings:
        includePostAccessBanner: true
      postLoginBannerSettings:
        includePostAccessBanner: true
      supportInfoSettings:
        defaultEmptyFieldValue: string
        emptyFieldDisplay: string
        includeBrowserUserAgent: true
        includeFailureCode: true
        includeIpAddress: true
        includeMacAddr: true
        includePolicyServer: true
        includeSupportInfoPage: true

- name: Delete by id
  cisco.ise.my_device_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.my_device_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: present
    customizations:
      globalCustomizations:
        backgroundImage:
          data: string
        bannerImage:
          data: string
        bannerTitle: string
        contactText: string
        desktopLogoImage:
          data: string
        footerElement: string
        mobileLogoImage:
          data: string
      language:
        viewLanguage: string
      pageCustomizations:
        data:
        - key: string
          value: string
      portalTheme:
        id: string
        name: string
        themeData: string
      portalTweakSettings:
        bannerColor: string
        bannerTextColor: string
        pageBackgroundColor: string
        pageLabelAndTextColor: string
    description: string
    name: string
    portalTestUrl: string
    portalType: string
    settings:
      aupSettings:
        displayFrequency: string
        displayFrequencyIntervalDays: 0
        includeAup: true
        requireScrolling: true
      employeeChangePasswordSettings:
        allowEmployeeToChangePwd: true
      loginPageSettings:
        aupDisplay: string
        includeAup: true
        maxFailedAttemptsBeforeRateLimit: 0
        requireAupAcceptance: true
        requireScrolling: true
        socialConfigs:
        - {}
        timeBetweenLoginsDuringRateLimit: 0
      portalSettings:
        allowedInterfaces:
        - string
        alwaysUsedLanguage: string
        certificateGroupTag: string
        displayLang: string
        endpointIdentityGroup: string
        fallbackLanguage: string
        httpsPort: 0
      postAccessBannerSettings:
        includePostAccessBanner: true
      postLoginBannerSettings:
        includePostAccessBanner: true
      supportInfoSettings:
        defaultEmptyFieldValue: string
        emptyFieldDisplay: string
        includeBrowserUserAgent: true
        includeFailureCode: true
        includeIpAddress: true
        includeMacAddr: true
        includePolicyServer: true
        includeSupportInfoPage: true

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
        "loginPageSettings": {
          "maxFailedAttemptsBeforeRateLimit": 0,
          "timeBetweenLoginsDuringRateLimit": 0,
          "includeAup": true,
          "aupDisplay": "string",
          "requireAupAcceptance": true,
          "requireScrolling": true,
          "socialConfigs": [
            {}
          ]
        },
        "aupSettings": {
          "displayFrequencyIntervalDays": 0,
          "displayFrequency": "string",
          "includeAup": true,
          "requireScrolling": true
        },
        "employeeChangePasswordSettings": {
          "allowEmployeeToChangePwd": true
        },
        "postLoginBannerSettings": {
          "includePostAccessBanner": true
        },
        "postAccessBannerSettings": {
          "includePostAccessBanner": true
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
