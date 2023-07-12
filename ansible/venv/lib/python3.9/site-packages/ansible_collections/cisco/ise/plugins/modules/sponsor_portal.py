#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sponsor_portal
short_description: Resource module for Sponsor Portal
description:
- Manage operations create, update and delete of the resource Sponsor Portal.
- This API creates a sponsor portal.
- This API deletes a sponsor portal by ID.
- This API allows the client to update a sponsor portal by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  customizations:
    description: Sponsor Portal's customizations.
    suboptions:
      globalCustomizations:
        description: Sponsor Portal's globalCustomizations.
        suboptions:
          backgroundImage:
            description: Sponsor Portal's backgroundImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerImage:
            description: Sponsor Portal's bannerImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerTitle:
            description: Sponsor Portal's bannerTitle.
            type: str
          contactText:
            description: Sponsor Portal's contactText.
            type: str
          desktopLogoImage:
            description: Sponsor Portal's desktopLogoImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          footerElement:
            description: Sponsor Portal's footerElement.
            type: str
          mobileLogoImage:
            description: Sponsor Portal's mobileLogoImage.
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
            description: Sponsor Portal's viewLanguage.
            type: str
        type: dict
      pageCustomizations:
        description: Sponsor Portal's pageCustomizations.
        suboptions:
          data:
            description: The Dictionary will be exposed here as key value pair.
            elements: dict
            suboptions:
              key:
                description: Sponsor Portal's key.
                type: str
              value:
                description: Sponsor Portal's value.
                type: str
            type: list
        type: dict
      portalTheme:
        description: Sponsor Portal's portalTheme.
        suboptions:
          id:
            description: Sponsor Portal's id.
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
            description: Sponsor Portal's bannerTextColor.
            type: str
          pageBackgroundColor:
            description: Sponsor Portal's pageBackgroundColor.
            type: str
          pageLabelAndTextColor:
            description: Sponsor Portal's pageLabelAndTextColor.
            type: str
        type: dict
    type: dict
  description:
    description: Sponsor Portal's description.
    type: str
  id:
    description: Sponsor Portal's id.
    type: str
  name:
    description: Sponsor Portal's name.
    type: str
  portalTestUrl:
    description: URL to bring up a test page for this portal.
    type: str
  portalType:
    description: Allowed values - BYOD, - HOTSPOTGUEST, - MYDEVICE, - SELFREGGUEST,
      - SPONSOR, - SPONSOREDGUEST.
    type: str
  settings:
    description: Defines all of the settings groups available for a portal.
    suboptions:
      aupSettings:
        description: Sponsor Portal's aupSettings.
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
            description: IncludeAup flag.
            type: bool
          requireScrolling:
            description: RequireScrolling flag.
            type: bool
        type: dict
      loginPageSettings:
        description: Portal Login Page settings groups follow.
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
          requireAupScrolling:
            description: RequireAupScrolling flag.
            type: bool
          socialConfigs:
            description: Sponsor Portal's socialConfigs.
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
          authenticationMethod:
            description: Unique Id of the identity source sequence.
            type: str
          availableSSIDs:
            description: Names of the SSIDs available for assignment to guest users
              by sponsors.
            elements: str
            type: list
          certificateGroupTag:
            description: Logical name of the x.509 server certificate that will be used
              for the portal.
            type: str
          displayLang:
            description: Allowed values - USEBROWSERLOCALE, - ALWAYSUSE.
            type: str
          fallbackLanguage:
            description: Used when displayLang = USEBROWSERLOCALE.
            type: str
          fqdn:
            description: The fully-qualified domain name (FQDN) that end-users will
              use to access this portal. Used only in Sponsor portal.
            type: str
          httpsPort:
            description: The port number that the allowed interfaces will listen on.
              Range from 8000 to 8999.
            type: int
          idleTimeout:
            description: Sponsor Portal's idleTimeout.
            type: int
        type: dict
      postAccessBannerSettings:
        description: Sponsor Portal's postAccessBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: IncludePostAccessBanner flag.
            type: bool
        type: dict
      postLoginBannerSettings:
        description: Sponsor Portal's postLoginBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: Include a Post-Login Banner page.
            type: bool
        type: dict
      sponsorChangePasswordSettings:
        description: Sponsor Portal's sponsorChangePasswordSettings.
        suboptions:
          allowSponsorToChangePwd:
            description: Allow sponsors to change their own passwords.
            type: bool
        type: dict
      supportInfoSettings:
        description: Sponsor Portal's supportInfoSettings.
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
    sponsor_portal.SponsorPortal.create_sponsor_portal,
    sponsor_portal.SponsorPortal.delete_sponsor_portal_by_id,
    sponsor_portal.SponsorPortal.update_sponsor_portal_by_id,

  - Paths used are
    post /ers/config/sponsorportal,
    delete /ers/config/sponsorportal/{id},
    put /ers/config/sponsorportal/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.sponsor_portal:
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
      loginPageSettings:
        aupDisplay: string
        includeAup: true
        maxFailedAttemptsBeforeRateLimit: 0
        requireAupAcceptance: true
        requireAupScrolling: true
        socialConfigs:
        - {}
        timeBetweenLoginsDuringRateLimit: 0
      portalSettings:
        allowedInterfaces:
        - string
        authenticationMethod: string
        availableSsids:
        - string
        certificateGroupTag: string
        displayLang: string
        fallbackLanguage: string
        fqdn: string
        httpsPort: 0
        idleTimeout: 0
      postAccessBannerSettings:
        includePostAccessBanner: true
      postLoginBannerSettings:
        includePostAccessBanner: true
      sponsorChangePasswordSettings:
        allowSponsorToChangePwd: true
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
  cisco.ise.sponsor_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sponsor_portal:
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
      loginPageSettings:
        aupDisplay: string
        includeAup: true
        maxFailedAttemptsBeforeRateLimit: 0
        requireAupAcceptance: true
        requireAupScrolling: true
        socialConfigs:
        - {}
        timeBetweenLoginsDuringRateLimit: 0
      portalSettings:
        allowedInterfaces:
        - string
        authenticationMethod: string
        availableSsids:
        - string
        certificateGroupTag: string
        displayLang: string
        fallbackLanguage: string
        fqdn: string
        httpsPort: 0
        idleTimeout: 0
      postAccessBannerSettings:
        includePostAccessBanner: true
      postLoginBannerSettings:
        includePostAccessBanner: true
      sponsorChangePasswordSettings:
        allowSponsorToChangePwd: true
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
          "fqdn": "string",
          "authenticationMethod": "string",
          "idleTimeout": 0,
          "displayLang": "string",
          "fallbackLanguage": "string",
          "availableSsids": [
            "string"
          ]
        },
        "loginPageSettings": {
          "maxFailedAttemptsBeforeRateLimit": 0,
          "timeBetweenLoginsDuringRateLimit": 0,
          "includeAup": true,
          "aupDisplay": "string",
          "requireAupAcceptance": true,
          "requireAupScrolling": true,
          "socialConfigs": [
            {}
          ]
        },
        "aupSettings": {
          "includeAup": true,
          "requireScrolling": true,
          "displayFrequency": "string",
          "displayFrequencyIntervalDays": 0
        },
        "sponsorChangePasswordSettings": {
          "allowSponsorToChangePwd": true
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
