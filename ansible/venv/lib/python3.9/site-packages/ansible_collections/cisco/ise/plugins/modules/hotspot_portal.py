#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: hotspot_portal
short_description: Resource module for Hotspot Portal
description:
- Manage operations create, update and delete of the resource Hotspot Portal.
- This API creates a hotspot portal.
- This API deletes a hotspot portal by ID.
- This API allows the client to update a hotspot portal by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  customizations:
    description: Defines all of the Portal Customizations available.
    suboptions:
      globalCustomizations:
        description: Hotspot Portal's globalCustomizations.
        suboptions:
          backgroundImage:
            description: Hotspot Portal's backgroundImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerImage:
            description: Hotspot Portal's bannerImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerTitle:
            description: Hotspot Portal's bannerTitle.
            type: str
          contactText:
            description: Hotspot Portal's contactText.
            type: str
          desktopLogoImage:
            description: Hotspot Portal's desktopLogoImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          footerElement:
            description: Hotspot Portal's footerElement.
            type: str
          mobileLogoImage:
            description: Hotspot Portal's mobileLogoImage.
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
            description: Hotspot Portal's viewLanguage.
            type: str
        type: dict
      pageCustomizations:
        description: Hotspot Portal's pageCustomizations.
        suboptions:
          data:
            description: Hotspot Portal's data.
            elements: dict
            suboptions:
              key:
                description: Hotspot Portal's key.
                type: str
              value:
                description: Hotspot Portal's value.
                type: str
            type: list
        type: dict
      portalTheme:
        description: Defines the configuration for portal theme.
        suboptions:
          id:
            description: The unique internal identifier of the portal theme.
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
            description: Hotspot Portal's bannerTextColor.
            type: str
          pageBackgroundColor:
            description: Hotspot Portal's pageBackgroundColor.
            type: str
          pageLabelAndTextColor:
            description: Hotspot Portal's pageLabelAndTextColor.
            type: str
        type: dict
    type: dict
  description:
    description: Hotspot Portal's description.
    type: str
  id:
    description: Hotspot Portal's id.
    type: str
  name:
    description: Hotspot Portal's name.
    type: str
  portalTestUrl:
    description: URL to bring up a test page for this portal.
    type: str
  portalType:
    description: Allowed values - BYOD, - HOTSPOTGUEST, - MYDEVICE, - SELFREGGUEST,
      - SPONSOR, - SPONSOREDGUEST.
    type: str
  settings:
    description: Defines all of the settings groups available for a BYOD.
    suboptions:
      aupSettings:
        description: Configuration of the Acceptable Use Policy (AUP) for a portal.
        suboptions:
          accessCode:
            description: Access code that must be entered by the portal user (only valid
              if requireAccessCode = true).
            type: str
          includeAup:
            description: Require the portal user to read and accept an AUP.
            type: bool
          requireAccessCode:
            description: Require the portal user to enter an access code. Only used
              in Hotspot portal.
            type: bool
          requireScrolling:
            description: Require the portal user to scroll to the end of the AUP. Only
              valid if requireAupAcceptance = true.
            type: bool
        type: dict
      authSuccessSettings:
        description: Hotspot Portal's authSuccessSettings.
        suboptions:
          redirectUrl:
            description: Target URL for redirection, used when successRedirect = URL.
            type: str
          successRedirect:
            description: After an Authentication Success where should device be redirected.
              Allowed values - AUTHSUCCESSPAGE, - ORIGINATINGURL, - URL.
            type: str
        type: dict
      portalSettings:
        description: The port, interface, certificate, and other basic settings of a
          portal.
        suboptions:
          allowedInterfaces:
            description: Interfaces that the portal will be reachable on. Allowed values
              - eth0 - eth1 - eth2 - eth3 - eth4 - eth5 - bond0 - bond1 - bond2.
            elements: str
            type: list
          alwaysUsedLanguage:
            description: Used when displayLang = ALWAYSUSE.
            type: str
          certificateGroupTag:
            description: Logical name of the x.509 server certificate that will be used
              for the portal.
            type: str
          coaType:
            description: Allowed Values - COAREAUTHENTICATE, - COATERMINATE.
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
        description: Hotspot Portal's postAccessBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: IncludePostAccessBanner flag.
            type: bool
        type: dict
      postLoginBannerSettings:
        description: Hotspot Portal's postLoginBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: Include a Post-Login Banner page.
            type: bool
        type: dict
      supportInfoSettings:
        description: Portal Support Information Settings.
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
    hotspot_portal.HotspotPortal.create_hotspot_portal,
    hotspot_portal.HotspotPortal.delete_hotspot_portal_by_id,
    hotspot_portal.HotspotPortal.update_hotspot_portal_by_id,

  - Paths used are
    post /ers/config/hotspotportal,
    delete /ers/config/hotspotportal/{id},
    put /ers/config/hotspotportal/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.hotspot_portal:
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
        accessCode: string
        includeAup: true
        requireAccessCode: true
        requireScrolling: true
      authSuccessSettings:
        redirectUrl: string
        successRedirect: string
      portalSettings:
        allowedInterfaces:
        - string
        alwaysUsedLanguage: string
        certificateGroupTag: string
        coaType: string
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
  cisco.ise.hotspot_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.hotspot_portal:
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
        accessCode: string
        includeAup: true
        requireAccessCode: true
        requireScrolling: true
      authSuccessSettings:
        redirectUrl: string
        successRedirect: string
      portalSettings:
        allowedInterfaces:
        - string
        alwaysUsedLanguage: string
        certificateGroupTag: string
        coaType: string
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
          "coaType": "string",
          "displayLang": "string",
          "fallbackLanguage": "string",
          "alwaysUsedLanguage": "string"
        },
        "aupSettings": {
          "requireAccessCode": true,
          "accessCode": "string",
          "includeAup": true,
          "requireScrolling": true
        },
        "postAccessBannerSettings": {
          "includePostAccessBanner": true
        },
        "authSuccessSettings": {
          "successRedirect": "string",
          "redirectUrl": "string"
        },
        "postLoginBannerSettings": {
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
          "backgroundImage": {
            "data": "string"
          },
          "bannerImage": {
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
