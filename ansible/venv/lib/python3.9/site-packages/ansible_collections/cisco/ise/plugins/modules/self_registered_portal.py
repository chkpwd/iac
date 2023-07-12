#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: self_registered_portal
short_description: Resource module for Self Registered Portal
description:
- Manage operations create, update and delete of the resource Self Registered Portal.
- This API creates a self registered portal.
- This API deletes a self registered portal by ID.
- This API allows the client to update a self registered portal by ID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.ise.module
author: Rafael Campos (@racampos)
options:
  customizations:
    description: Defines all of the Portal Customizations available.
    suboptions:
      globalCustomizations:
        description: Self Registered Portal's globalCustomizations.
        suboptions:
          backgroundImage:
            description: Self Registered Portal's backgroundImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerImage:
            description: Self Registered Portal's bannerImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          bannerTitle:
            description: Self Registered Portal's bannerTitle.
            type: str
          contactText:
            description: Self Registered Portal's contactText.
            type: str
          desktopLogoImage:
            description: Self Registered Portal's desktopLogoImage.
            suboptions:
              data:
                description: Represented as base 64 encoded string of the image byte
                  array.
                type: str
            type: dict
          footerElement:
            description: Self Registered Portal's footerElement.
            type: str
          mobileLogoImage:
            description: Self Registered Portal's mobileLogoImage.
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
            description: Self Registered Portal's viewLanguage.
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
                description: Self Registered Portal's key.
                type: str
              value:
                description: Self Registered Portal's value.
                type: str
            type: list
        type: dict
      portalTheme:
        description: Self Registered Portal's portalTheme.
        suboptions:
          id:
            description: Self Registered Portal's id.
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
            description: Self Registered Portal's bannerTextColor.
            type: str
          pageBackgroundColor:
            description: Self Registered Portal's pageBackgroundColor.
            type: str
          pageLabelAndTextColor:
            description: Self Registered Portal's pageLabelAndTextColor.
            type: str
        type: dict
    type: dict
  description:
    description: Self Registered Portal's description.
    type: str
  id:
    description: Self Registered Portal's id.
    type: str
  name:
    description: Self Registered Portal's name.
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
        description: Self Registered Portal's aupSettings.
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
          requireAupScrolling:
            description: Require the portal user to scroll to the end of the AUP. Only
              valid if requireAupAcceptance = true.
            type: bool
          requireScrolling:
            description: RequireScrolling flag.
            type: bool
          skipAupForEmployees:
            description: Only valid if requireAupAcceptance = trueG.
            type: bool
          useDiffAupForEmployees:
            description: Only valid if requireAupAcceptance = trueG.
            type: bool
        type: dict
      authSuccessSettings:
        description: Self Registered Portal's authSuccessSettings.
        suboptions:
          redirectUrl:
            description: Self Registered Portal's redirectUrl.
            type: str
          successRedirect:
            description: Self Registered Portal's successRedirect.
            type: str
        type: dict
      byodSettings:
        description: Configuration of BYOD Device Welcome, Registration and Success
          steps.
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
            description: Configuration of BYOD endpoint Registration Success step configuration.
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
            description: Configuration of BYOD endpoint welcome step configuration.
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
                  AUP, Only valid if includeAup = true.
                type: bool
            type: dict
        type: dict
      guestChangePasswordSettings:
        description: Self Registered Portal's guestChangePasswordSettings.
        suboptions:
          allowChangePasswdAtFirstLogin:
            description: Allow guest to change their own passwords.
            type: bool
        type: dict
      guestDeviceRegistrationSettings:
        description: Self Registered Portal's guestDeviceRegistrationSettings.
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
          allowGuestToUseSocialAccounts:
            description: AllowGuestToUseSocialAccounts flag.
            type: bool
          allowShowGuestForm:
            description: AllowShowGuestForm flag.
            type: bool
          alternateGuestPortal:
            description: Self Registered Portal's alternateGuestPortal.
            type: str
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
            description: Require the portal user to enter an access code.
            type: bool
          requireAupAcceptance:
            description: Require the portal user to accept the AUP. Only valid if includeAup
              = true.
            type: bool
          socialConfigs:
            description: Self Registered Portal's socialConfigs.
            elements: dict
            suboptions:
              socialMediaType:
                description: Self Registered Portal's socialMediaType.
                type: str
              socialMediaValue:
                description: Self Registered Portal's socialMediaValue.
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
            description: Self Registered Portal's alwaysUsedLanguage.
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
        description: Self Registered Portal's postAccessBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: IncludePostAccessBanner flag.
            type: bool
        type: dict
      postLoginBannerSettings:
        description: Self Registered Portal's postLoginBannerSettings.
        suboptions:
          includePostAccessBanner:
            description: Include a Post-Login Banner page.
            type: bool
        type: dict
      selfRegPageSettings:
        description: Self Registered Portal's selfRegPageSettings.
        suboptions:
          accountValidityDuration:
            description: Self-registered guest account is valid for this many account_validity_time_units.
            type: int
          accountValidityTimeUnits:
            description: Time units for account_validity_duration. Allowed Values -
              DAYS, - HOURS, - MINUTES.
            type: str
          allowGraceAccess:
            description: AllowGraceAccess flag.
            type: bool
          approvalEmailAddresses:
            description: Only valid if requireGuestApproval = true and sendApprovalRequestTo
              = SELECTEDEMAILADDRESSES.
            type: str
          approveDenyLinksTimeUnits:
            description: This attribute, along with approveDenyLinksValidFor, specifies
              how long the link can be used. Only valid if requireGuestApproval = true.
              Allowed Values - DAYS, - HOURS, - MINUTES.
            type: str
          approveDenyLinksValidFor:
            description: This attribute, along with approveDenyLinksTimeUnits, specifies
              how long the link can be used. Only valid if requireGuestApproval = true.
            type: int
          assignGuestsToGuestType:
            description: Guests are assigned to this guest type.
            type: str
          aupDisplay:
            description: How the AUP should be displayed, either on page or as a link.
              Only valid if includeAup = true. Allowed values - ONPAGE, - ASLINK.
            type: str
          authenticateSponsorsUsingPortalList:
            description: AuthenticateSponsorsUsingPortalList flag.
            type: bool
          autoLoginSelfWait:
            description: Allow guests to login automatically from self-registration
              after sponsor's approval. No need to provide the credentials by guest
              to login.
            type: bool
          autoLoginTimePeriod:
            description: Waiting period for auto login until sponsor's approval. If
              time exceeds, guest has to login manually by providing the credentials.
              Default value is 5 minutes.
            type: int
          credentialNotificationUsingEmail:
            description: If true, send credential notification upon approval using email.
              Only valid if requireGuestApproval = true.
            type: bool
          credentialNotificationUsingSMS:
            description: If true, send credential notification upon approval using SMS.
              Only valid if requireGuestApproval = true.
            type: bool
          enableGuestEmailBlacklist:
            description: Disallow guests with an e-mail address from selected domains.
            type: bool
          enableGuestEmailWhitelist:
            description: Allow guests with an e-mail address from selected domains.
            type: bool
          fieldCompany:
            description: Self Registered Portal's fieldCompany.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldEmailAddr:
            description: Self Registered Portal's fieldEmailAddr.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldFirstName:
            description: Self Registered Portal's fieldFirstName.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldLastName:
            description: Self Registered Portal's fieldLastName.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldLocation:
            description: Self Registered Portal's fieldLocation.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldPersonBeingVisited:
            description: Self Registered Portal's fieldPersonBeingVisited.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldPhoneNo:
            description: Self Registered Portal's fieldPhoneNo.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldReasonForVisit:
            description: Self Registered Portal's fieldReasonForVisit.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldSMSProvider:
            description: Self Registered Portal's fieldSMSProvider.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          fieldUserName:
            description: Self Registered Portal's fieldUserName.
            suboptions:
              include:
                description: Include flag.
                type: bool
              require:
                description: Only applicable if include = true.
                type: bool
            type: dict
          graceAccessExpireInterval:
            description: Self Registered Portal's graceAccessExpireInterval.
            type: int
          graceAccessSendAccountExpiration:
            description: GraceAccessSendAccountExpiration flag.
            type: bool
          guestEmailBlacklistDomains:
            description: Disallow guests with an e-mail address from selected domains.
            elements: str
            type: list
          guestEmailWhitelistDomains:
            description: Self-registered guests whose e-mail address is in one of these
              domains will be allowed. Only valid if enableGuestEmailWhitelist = true.
            elements: str
            type: list
          includeAup:
            description: Include an Acceptable Use Policy (AUP) that should be displayed
              during login.
            type: bool
          postRegistrationRedirect:
            description: After the registration submission direct the guest user to
              one of the following pages. Only valid if requireGuestApproval = true.
              Allowed Values - SELFREGISTRATIONSUCCESS, - LOGINPAGEWITHINSTRUCTIONS
              - URL.
            type: str
          postRegistrationRedirectUrl:
            description: URL where guest user is redirected after registration. Only
              valid if requireGuestApproval = true and postRegistrationRedirect = URL.
            type: str
          registrationCode:
            description: The registration code that the guest user must enter.
            type: str
          requireApproverToAuthenticate:
            description: When self-registered guests require approval, an approval request
              is e-mailed to one or more sponsor users. If the Cisco ISE Administrator
              chooses to include an approval link in the e-mail, a sponsor user who
              clicks the link will be required to enter their username and password
              if this attribute is true. Only valid if requireGuestApproval = true.
            type: bool
          requireAupAcceptance:
            description: Require the portal user to accept the AUP. Only valid if includeAup
              = true.
            type: bool
          requireGuestApproval:
            description: Require self-registered guests to be approved if true.
            type: bool
          requireRegistrationCode:
            description: Self-registered guests are required to enter a registration
              code.
            type: bool
          selectableLocations:
            description: Guests can choose from these locations to set their time zone.
            elements: str
            type: list
          selectableSMSProviders:
            description: This attribute is an array of SMS provider names.
            elements: str
            type: list
          sendApprovalRequestTo:
            description: Specifies where approval requests are sent. Only valid if requireGuestApproval
              = true. Allowed Values - SELECTEDEMAILADDRESSES, - PERSONBEINGVISITED.
            type: str
          sponsorPortalList:
            description: Self Registered Portal's sponsorPortalList.
            elements: str
            type: list
        type: dict
      selfRegSuccessSettings:
        description: Self Registered Portal's selfRegSuccessSettings.
        suboptions:
          allowGuestLoginFromSelfregSuccessPage:
            description: AllowGuestLoginFromSelfregSuccessPage flag.
            type: bool
          allowGuestSendSelfUsingEmail:
            description: AllowGuestSendSelfUsingEmail flag.
            type: bool
          allowGuestSendSelfUsingPrint:
            description: AllowGuestSendSelfUsingPrint flag.
            type: bool
          allowGuestSendSelfUsingSMS:
            description: AllowGuestSendSelfUsingSMS flag.
            type: bool
          aupOnPage:
            description: AupOnPage flag.
            type: bool
          includeAup:
            description: IncludeAup flag.
            type: bool
          includeCompany:
            description: IncludeCompany flag.
            type: bool
          includeEmailAddr:
            description: IncludeEmailAddr flag.
            type: bool
          includeFirstName:
            description: IncludeFirstName flag.
            type: bool
          includeLastName:
            description: IncludeLastName flag.
            type: bool
          includeLocation:
            description: IncludeLocation flag.
            type: bool
          includePassword:
            description: IncludePassword flag.
            type: bool
          includePersonBeingVisited:
            description: IncludePersonBeingVisited flag.
            type: bool
          includePhoneNo:
            description: IncludePhoneNo flag.
            type: bool
          includeReasonForVisit:
            description: IncludeReasonForVisit flag.
            type: bool
          includeSMSProvider:
            description: IncludeSMSProvider flag.
            type: bool
          includeUserName:
            description: IncludeUserName flag.
            type: bool
          requireAupAcceptance:
            description: RequireAupAcceptance flag.
            type: bool
          requireAupScrolling:
            description: RequireAupScrolling flag.
            type: bool
        type: dict
      supportInfoSettings:
        description: Self Registered Portal's supportInfoSettings.
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
seealso:
- name: Cisco ISE documentation for SelfRegisteredPortal
  description: Complete reference of the SelfRegisteredPortal API.
  link: https://developer.cisco.com/docs/identity-services-engine/v1/#!selfregportal
notes:
  - SDK Method used are
    self_registered_portal.SelfRegisteredPortal.create_self_registered_portal,
    self_registered_portal.SelfRegisteredPortal.delete_self_registered_portal_by_id,
    self_registered_portal.SelfRegisteredPortal.update_self_registered_portal_by_id,

  - Paths used are
    post /ers/config/selfregportal,
    delete /ers/config/selfregportal/{id},
    put /ers/config/selfregportal/{id},

"""

EXAMPLES = r"""
- name: Update by id
  cisco.ise.self_registered_portal:
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
        allowGuestToUseSocialAccounts: true
        allowShowGuestForm: true
        alternateGuestPortal: string
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
      selfRegPageSettings:
        accountValidityDuration: 0
        accountValidityTimeUnits: string
        allowGraceAccess: true
        approvalEmailAddresses: string
        approveDenyLinksTimeUnits: string
        approveDenyLinksValidFor: 0
        assignGuestsToGuestType: string
        aupDisplay: string
        authenticateSponsorsUsingPortalList: true
        autoLoginSelfWait: true
        autoLoginTimePeriod: 0
        credentialNotificationUsingEmail: true
        credentialNotificationUsingSms: true
        enableGuestEmailBlacklist: true
        enableGuestEmailWhitelist: true
        fieldCompany:
          include: true
          require: true
        fieldEmailAddr:
          include: true
          require: true
        fieldFirstName:
          include: true
          require: true
        fieldLastName:
          include: true
          require: true
        fieldLocation:
          include: true
          require: true
        fieldPersonBeingVisited:
          include: true
          require: true
        fieldPhoneNo:
          include: true
          require: true
        fieldReasonForVisit:
          include: true
          require: true
        fieldSmsProvider:
          include: true
          require: true
        fieldUserName:
          include: true
          require: true
        graceAccessExpireInterval: 0
        graceAccessSendAccountExpiration: true
        guestEmailBlacklistDomains:
        - string
        guestEmailWhitelistDomains:
        - string
        includeAup: true
        postRegistrationRedirect: string
        postRegistrationRedirectUrl: string
        registrationCode: string
        requireApproverToAuthenticate: true
        requireAupAcceptance: true
        requireGuestApproval: true
        requireRegistrationCode: true
        selectableLocations:
        - string
        selectableSmsProviders:
        - string
        sendApprovalRequestTo: string
        sponsorPortalList:
        - string
      selfRegSuccessSettings:
        allowGuestLoginFromSelfregSuccessPage: true
        allowGuestSendSelfUsingEmail: true
        allowGuestSendSelfUsingPrint: true
        allowGuestSendSelfUsingSms: true
        aupOnPage: true
        includeAup: true
        includeCompany: true
        includeEmailAddr: true
        includeFirstName: true
        includeLastName: true
        includeLocation: true
        includePassword: true
        includePersonBeingVisited: true
        includePhoneNo: true
        includeReasonForVisit: true
        includeSmsProvider: true
        includeUserName: true
        requireAupAcceptance: true
        requireAupScrolling: true
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
  cisco.ise.self_registered_portal:
    ise_hostname: "{{ise_hostname}}"
    ise_username: "{{ise_username}}"
    ise_password: "{{ise_password}}"
    ise_verify: "{{ise_verify}}"
    state: absent
    id: string

- name: Create
  cisco.ise.self_registered_portal:
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
        allowGuestToUseSocialAccounts: true
        allowShowGuestForm: true
        alternateGuestPortal: string
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
      selfRegPageSettings:
        accountValidityDuration: 0
        accountValidityTimeUnits: string
        allowGraceAccess: true
        approvalEmailAddresses: string
        approveDenyLinksTimeUnits: string
        approveDenyLinksValidFor: 0
        assignGuestsToGuestType: string
        aupDisplay: string
        authenticateSponsorsUsingPortalList: true
        autoLoginSelfWait: true
        autoLoginTimePeriod: 0
        credentialNotificationUsingEmail: true
        credentialNotificationUsingSms: true
        enableGuestEmailBlacklist: true
        enableGuestEmailWhitelist: true
        fieldCompany:
          include: true
          require: true
        fieldEmailAddr:
          include: true
          require: true
        fieldFirstName:
          include: true
          require: true
        fieldLastName:
          include: true
          require: true
        fieldLocation:
          include: true
          require: true
        fieldPersonBeingVisited:
          include: true
          require: true
        fieldPhoneNo:
          include: true
          require: true
        fieldReasonForVisit:
          include: true
          require: true
        fieldSmsProvider:
          include: true
          require: true
        fieldUserName:
          include: true
          require: true
        graceAccessExpireInterval: 0
        graceAccessSendAccountExpiration: true
        guestEmailBlacklistDomains:
        - string
        guestEmailWhitelistDomains:
        - string
        includeAup: true
        postRegistrationRedirect: string
        postRegistrationRedirectUrl: string
        registrationCode: string
        requireApproverToAuthenticate: true
        requireAupAcceptance: true
        requireGuestApproval: true
        requireRegistrationCode: true
        selectableLocations:
        - string
        selectableSmsProviders:
        - string
        sendApprovalRequestTo: string
        sponsorPortalList:
        - string
      selfRegSuccessSettings:
        allowGuestLoginFromSelfregSuccessPage: true
        allowGuestSendSelfUsingEmail: true
        allowGuestSendSelfUsingPrint: true
        allowGuestSendSelfUsingSms: true
        aupOnPage: true
        includeAup: true
        includeCompany: true
        includeEmailAddr: true
        includeFirstName: true
        includeLastName: true
        includeLocation: true
        includePassword: true
        includePersonBeingVisited: true
        includePhoneNo: true
        includeReasonForVisit: true
        includeSmsProvider: true
        includeUserName: true
        requireAupAcceptance: true
        requireAupScrolling: true
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
