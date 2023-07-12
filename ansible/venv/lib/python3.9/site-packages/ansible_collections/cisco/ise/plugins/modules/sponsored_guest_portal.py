#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sponsored_guest_portal
short_description: Resource module for Sponsored Guest Portal
description:
- Manage operations create, update and delete of the resource Sponsored Guest Portal.
- This API creates a sponsored guest portal.
- This API deletes a sponsored guest portal by ID.
- This API allows the client to update a sponsored guest portal by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  customizations:
    description: Defines all of the Portal Customizations available.
    suboptions:
      globalCustomizations:
        description: Sponsored Guest Portal's globalCustomizations.
        suboptions:
          backgroundImage:
            description: Sponsored Guest Portal's backgroundImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerImage:
            description: Sponsored Guest Portal's bannerImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerTitle:
            description: Sponsored Guest Portal's bannerTitle.
            type: str
          contactText:
            description: Sponsored Guest Portal's contactText.
            type: str
          desktopLogoImage:
            description: Sponsored Guest Portal's desktopLogoImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          footerElement:
            description: Sponsored Guest Portal's footerElement.
            type: str
          mobileLogoImage:
            description: Sponsored Guest Portal's mobileLogoImage.
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
            description: Sponsored Guest Portal's viewLanguage.
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
                description: Sponsored Guest Portal's key.
                type: str
              value:
                description: Sponsored Guest Portal's value.
                type: str
            type: list
        type: dict
      portalTheme:
        description: Sponsored Guest Portal's portalTheme.
        suboptions:
          id:
            description: Sponsored Guest Portal's id.
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
            description: Sponsored Guest Portal's bannerTextColor.
            type: str
          pageBackgroundColor:
            description: Sponsored Guest Portal's pageBackgroundColor.
            type: str
          pageLabelAndTextColor:
            description: Sponsored Guest Portal's pageLabelAndTextColor.
            type: str
        type: dict
    type: dict
  description:
    description: Sponsored Guest Portal's description.
    type: str
  id:
    description: Sponsored Guest Portal's id.
    type: str
  name:
    description: Sponsored Guest Portal's name.
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
        description: Sponsored Guest Portal's aupSettings.
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
          requireAupScrolling:
            description: Require the portal user to scroll to the end of the AUP. Only
              valid if requireAupAcceptance = true.
            type: bool
          requireScrolling:
            description: RequireScrolling flag.
            type: bool
          skipAupForEmployees:
            description: Only valid if requireAupAcceptance = true.
            type: bool
          useDiffAupForEmployees:
            description: Only valid if requireAupAcceptance = true.
            type: bool
        type: dict
      authSuccessSettings:
        description: Sponsored Guest Portal's authSuccessSettings.
        suboptions:
          redirectUrl:
            description: Target URL for redirection, used when successRedirect = URL.
            type: str
          successRedirect:
            description: After an Authentication Success where should device be redirected.
              Allowed values - AUTHSUCCESSPAGE, - ORIGINATINGURL, - URL.
            type: str
        type: dict
      byodSettings:
        description: Sponsored Guest Portal's byodSettings.
        suboptions:
          byodRegistrationSettings:
            description: Configuration of BYOD endpoint Registration step configuration.
            suboptions:
              endPointIdentityGroupId:
                description: Identity group id for which endpoint belongs.
                type: str
              showDeviceID:
                description: Display Device ID field during registration.
                type: bool
            type: dict
          byodRegistrationSuccessSettings:
            description: Sponsored Guest Portal's byodRegistrationSuccessSettings.
            suboptions:
              redirectUrl:
                description: Target URL for redirection, used when successRedirect =
                  URL.
                type: str
              successRedirect:
                description: After an Authentication Success where should device be
                  redirected. Allowed values - AUTHSUCCESSPAGE, - ORIGINATINGURL, -
                  URL.
                type: str
            type: dict
          byodWelcomeSettings:
            description: Sponsored Guest Portal's byodWelcomeSettings.
            suboptions:
              aupDisplay:
                description: How the AUP should be displayed, either on page or as a
                  link. Only valid if includeAup = true. Allowed values - ONPAGE, -
                  ASLINK.
                type: str
              enableBYOD:
                description: EnableBYOD flag.
                type: bool
              enableGuestAccess:
                description: EnableGuestAccess flag.
                type: bool
              includeAup:
                description: IncludeAup flag.
                type: bool
              requireAupAcceptance:
                description: RequireAupAcceptance flag.
                type: bool
              requireMDM:
                description: RequireMDM flag.
                type: bool
              requireScrolling:
                description: Require BYOD devices to scroll down to the bottom of the
                  AUP. Only valid if includeAup = true.
                type: bool
            type: dict
        type: dict
      guestChangePasswordSettings:
        description: Sponsored Guest Portal's guestChangePasswordSettings.
        suboptions:
          allowChangePasswdAtFirstLogin:
            description: Allow guest to change their own passwords.
            type: bool
        type: dict
      guestDeviceRegistrationSettings:
        description: Sponsored Guest Portal's guestDeviceRegistrationSettings.
        suboptions:
          allowGuestsToRegisterDevices:
            description: Allow guests to register devices.
            type: bool
          autoRegisterGuestDevices:
            description: Automatically register guest devices.
            type: bool
        type: dict
      loginPageSettings:
        description: Portal Login Page settings groups follow.
        suboptions:
          accessCode:
            description: Access code that must be entered by the portal user (only valid
              if requireAccessCode = true).
            type: str
          allowAlternateGuestPortal:
            description: AllowAlternateGuestPortal flag.
            type: bool
          allowForgotPassword:
            description: AllowForgotPassword flag.
            type: bool
          allowGuestToChangePassword:
            description: Require the portal user to enter an access code.
            type: bool
          allowGuestToCreateAccounts:
            description: AllowGuestToCreateAccounts flag.
            type: bool
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
          requireAccessCode:
            description: RequireAccessCode flag.
            type: bool
          requireAupAcceptance:
            description: Require the portal user to accept the AUP. Only valid if includeAup
              = true.
            type: bool
          socialConfigs:
            description: Sponsored Guest Portal's socialConfigs.
            elements: dict
            suboptions:
              socialMediaType:
                description: Sponsored Guest Portal's socialMediaType.
                type: str
              socialMediaValue:
                description: Sponsored Guest Portal's socialMediaValue.
                type: str
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
            description: Sponsored Guest Portal's alwaysUsedLanguage.
            type: str
          assignedGuestTypeForEmployee:
            description: Unique Id of a guest type. Employees using this portal as a
              guest inherit login options from the guest type.
            type: str
          authenticationMethod:
            description: Unique Id of the identity source sequence.
            type: str
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
          httpsPort:
            description: The port number that the allowed interfaces will listen on.
              Range from 8000 to 8999.
            type: int
        type: dict
      postAccessBannerSettings:
        description: Sponsored Guest Portal's postAccessBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: IncludePostAccessBanner flag.
            type: bool
        type: dict
      postLoginBannerSettings:
        description: Sponsored Guest Portal's postLoginBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: Include a Post-Login Banner page.
            type: bool
        type: dict
      supportInfoSettings:
        description: Sponsored Guest Portal's supportInfoSettings.
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
    sponsored_guest_portal.SponsoredGuestPortal.create_sponsored_guest_portal,
    sponsored_guest_portal.SponsoredGuestPortal.delete_sponsored_guest_portal_by_id,
    sponsored_guest_portal.SponsoredGuestPortal.update_sponsored_guest_portal_by_id,

  - Paths used are
    post /ers/config/sponsoredguestportal,
    delete /ers/config/sponsoredguestportal/{id},
    put /ers/config/sponsoredguestportal/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.sponsored_guest_portal:
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
        requireAupScrolling: true
        requireScrolling: true
        skipAupForEmployees: true
        useDiffAupForEmployees: true
      authSuccessSettings:
        redirectUrl: string
        successRedirect: string
      byodSettings:
        byodRegistrationSettings:
          endPointIdentityGroupId: string
          showDeviceID: true
        byodRegistrationSuccessSettings:
          redirectUrl: string
          successRedirect: string
        byodWelcomeSettings:
          aupDisplay: string
          enableBYOD: true
          enableGuestAccess: true
          includeAup: true
          requireAupAcceptance: true
          requireMDM: true
          requireScrolling: true
      guestChangePasswordSettings:
        allowChangePasswdAtFirstLogin: true
      guestDeviceRegistrationSettings:
        allowGuestsToRegisterDevices: true
        autoRegisterGuestDevices: true
      loginPageSettings:
        accessCode: string
        allowAlternateGuestPortal: true
        allowForgotPassword: true
        allowGuestToChangePassword: true
        allowGuestToCreateAccounts: true
        aupDisplay: string
        includeAup: true
        maxFailedAttemptsBeforeRateLimit: 0
        requireAccessCode: true
        requireAupAcceptance: true
        socialConfigs:
        - socialMediaType: string
          socialMediaValue: string
        timeBetweenLoginsDuringRateLimit: 0
      portalSettings:
        allowedInterfaces:
        - string
        alwaysUsedLanguage: string
        assignedGuestTypeForEmployee: string
        authenticationMethod: string
        certificateGroupTag: string
        displayLang: string
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
  cisco.ise.sponsored_guest_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.sponsored_guest_portal:
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
        requireAupScrolling: true
        requireScrolling: true
        skipAupForEmployees: true
        useDiffAupForEmployees: true
      authSuccessSettings:
        redirectUrl: string
        successRedirect: string
      byodSettings:
        byodRegistrationSettings:
          endPointIdentityGroupId: string
          showDeviceID: true
        byodRegistrationSuccessSettings:
          redirectUrl: string
          successRedirect: string
        byodWelcomeSettings:
          aupDisplay: string
          enableBYOD: true
          enableGuestAccess: true
          includeAup: true
          requireAupAcceptance: true
          requireMDM: true
          requireScrolling: true
      guestChangePasswordSettings:
        allowChangePasswdAtFirstLogin: true
      guestDeviceRegistrationSettings:
        allowGuestsToRegisterDevices: true
        autoRegisterGuestDevices: true
      loginPageSettings:
        accessCode: string
        allowAlternateGuestPortal: true
        allowForgotPassword: true
        allowGuestToChangePassword: true
        allowGuestToCreateAccounts: true
        aupDisplay: string
        includeAup: true
        maxFailedAttemptsBeforeRateLimit: 0
        requireAccessCode: true
        requireAupAcceptance: true
        socialConfigs:
        - socialMediaType: string
          socialMediaValue: string
        timeBetweenLoginsDuringRateLimit: 0
      portalSettings:
        allowedInterfaces:
        - string
        alwaysUsedLanguage: string
        assignedGuestTypeForEmployee: string
        authenticationMethod: string
        certificateGroupTag: string
        displayLang: string
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
          "socialConfigs": [
            {
              "socialMediaType": "string",
              "socialMediaValue": "string"
            }
          ]
        },
        "aupSettings": {
          "includeAup": true,
          "requireAupScrolling": true,
          "useDiffAupForEmployees": true,
          "skipAupForEmployees": true,
          "displayFrequencyIntervalDays": 0,
          "requireScrolling": true,
          "displayFrequency": "string"
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
