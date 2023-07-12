#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = ("Madhan Sankaranarayanan, Rishita Chowdhary")

DOCUMENTATION = r"""
---
module: swim_intent
short_description: Intent module for SWIM related functions
description:
- Manage operation related to image importation, distribution, activation and tagging image as golden
- API to fetch a software image from remote file system using URL for HTTP/FTP and upload it to DNA Center.
  Supported image files extensions are bin, img, tar, smu, pie, aes, iso, ova, tar_gz and qcow2.
- API to fetch a software image from local file system and upload it to DNA Center
  Supported image files extensions are bin, img, tar, smu, pie, aes, iso, ova, tar_gz and qcow2.
- API to tag/untag image as golen for a given family of devices
- API to distribute a software image on a given device. Software image must be imported successfully into
  DNA Center before it can be distributed.
- API to activate a software image on a given device. Software image must be present in the device flash.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Madhan Sankaranarayanan (@madhansansel)
        Rishita Chowdhary (@rishitachowdhary)
options:
  config:
    description: List of details of SWIM image being managed
    type: list
    elements: dict
    required: True
    suboptions:
      importImageDetails:
        description: Details of image being imported
        type: dict
        suboptions:
          type:
            description: The source of import, supports url import or local import.
            type: str
          localImageDetails:
            description: Details of the local path of the image to be imported.
            type: dict
            suboptions:
              filePath:
                description: File absolute path.
                type: str
              isThirdParty:
                description: IsThirdParty query parameter. Third party Image check.
                type: bool
              thirdPartyApplicationType:
                description: ThirdPartyApplicationType query parameter. Third Party Application Type.
                type: str
              thirdPartyImageFamily:
                description: ThirdPartyImageFamily query parameter. Third Party image family.
                type: str
              thirdPartyVendor:
                description: ThirdPartyVendor query parameter. Third Party Vendor.
                type: str
          urlDetails:
            description: URL details for SWIM import
            type: dict
            suboptions:
              payload:
                description: Swim Import Via Url's payload.
                type: list
                elements: dict
                suboptions:
                  applicationType:
                    description: Swim Import Via Url's applicationType.
                    type: str
                  imageFamily:
                    description: Swim Import Via Url's imageFamily.
                    type: str
                  sourceURL:
                    description: Swim Import Via Url's sourceURL.
                    type: str
                  thirdParty:
                    description: ThirdParty flag.
                    type: bool
                  vendor:
                    description: Swim Import Via Url's vendor.
                    type: str
              scheduleAt:
                description: ScheduleAt query parameter. Epoch Time (The number of milli-seconds since
                  January 1 1970 UTC) at which the distribution should be scheduled (Optional).
                type: str
              scheduleDesc:
                description: ScheduleDesc query parameter. Custom Description (Optional).
                type: str
              scheduleOrigin:
                description: ScheduleOrigin query parameter. Originator of this call (Optional).
                type: str
      taggingDetails:
        description: Details for tagging or untagging an image as golden
        type: dict
        suboptions:
          imageName:
            description: SWIM image name which will be tagged or untagged as golden.
            type: str
          deviceRole:
            description: Device Role. Permissible Values ALL, UNKNOWN, ACCESS, BORDER ROUTER,
              DISTRIBUTION and CORE.
            type: str
          deviceFamilyName:
            description: Device family name
            type: str
          siteName:
            description: Site name for which SWIM image will be tagged/untagged as golden.
              If not provided, SWIM image will be mapped to global site.
            type: str
          tagging:
            description: Booelan value to tag/untag SWIM image as golden
              If True then the given image will be tagged as golden.
              If False then the given image will be un-tagged as golden.
            type: bool
      imageDistributionDetails:
        description: Details for SWIM image distribution. Device on which the image needs to distributed
          can be speciifed using any of the following parameters - deviceSerialNumber,
          deviceIPAddress, deviceHostname or deviceMacAddress.
        type: dict
        suboptions:
          imageName:
            description: SWIM image's name
            type: str
          deviceSerialNumber:
            description: Device serial number where the image needs to be distributed
            type: str
          deviceIPAddress:
            description: Device IP address where the image needs to be distributed
            type: str
          deviceHostname:
            description: Device hostname where the image needs to be distributed
            type: str
          deviceMacAddress:
            description: Device MAC address where the image needs to be distributed
            type: str
      imageActivationDetails:
        description: Details for SWIM image activation. Device on which the image needs to activated
          can be speciifed using any of the following parameters - deviceSerialNumber,
          deviceIPAddress, deviceHostname or deviceMacAddress.
        type: dict
        suboptions:
          activateLowerImageVersion:
            description: ActivateLowerImageVersion flag.
            type: bool
          deviceUpgradeMode:
            description: Swim Trigger Activation's deviceUpgradeMode.
            type: str
          distributeIfNeeded:
            description: DistributeIfNeeded flag.
            type: bool
          imageName:
            description: SWIM image's name
            type: str
          deviceSerialNumber:
            description: Device serial number where the image needs to be activated
            type: str
          deviceIPAddress:
            description: Device IP address where the image needs to be activated
            type: str
          deviceHostname:
            description: Device hostname where the image needs to be activated
            type: str
          deviceMacAddress:
            description: Device MAC address where the image needs to be activated
            type: str
          scheduleValidate:
            description: ScheduleValidate query parameter. ScheduleValidate, validates data
              before schedule (Optional).
            type: bool
requirements:
- dnacentersdk == 2.4.5
- python >= 3.5
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.import_software_image_via_url,
    software_image_management_swim.SoftwareImageManagementSwim.tag_as_golden_image,
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_distribution,
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_activation,

  - Paths used are
    post /dna/intent/api/v1/image/importation/source/url,
    post /dna/intent/api/v1/image/importation/golden,
    post /dna/intent/api/v1/image/distribution,
    post /dna/intent/api/v1/image/activation/device,

"""

EXAMPLES = r"""
- name: Import an image from a URL, tag it as golden and load it on device
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: True
    config:
    - importImageDetails:
        type: string
        urlDetails:
          payload:
          - sourceURL: string
            isThirdParty: bool
            imageFamily: string
            vendor: string
            applicationType: string
          scheduleAt: string
          scheduleDesc: string
          scheduleOrigin: string
      taggingDetails:
        imageName: string
        deviceRole: string
        deviceFamilyName: string
        siteName: string
        tagging: bool
      imageDistributionDetails:
        imageName: string
        deviceSerialNumber: string
      imageActivationDetails:
        scheduleValidate: bool
        activateLowerImageVersion: bool
        distributeIfNeeded: bool
        deviceSerialNumber: string
        imageName: string
"""

RETURN = r"""
#Case: SWIM image is successfully imported, tagged as golden, distributed and activated on a device
response:
  description: A dictionary with activation details as returned by the DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
                        "additionalStatusURL": String,
                        "data": String,
                        "endTime": 0,
                        "id": String,
                        "instanceTenantId": String,
                        "isError": bool,
                        "lastUpdate": 0,
                        "progress": String,
                        "rootId": String,
                        "serviceType": String,
                        "startTime": 0,
                        "version": 0
                  },
      "msg": String
    }

"""

import copy
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DNACSDK,
    validate_list_of_dicts,
    log,
    get_dict_result,
)
from ansible.module_utils.basic import AnsibleModule


class DnacSwims:

    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.config = copy.deepcopy(module.params.get("config"))
        self.have = {}
        self.want_create = {}
        self.diff_create = []
        self.validated = []
        dnac_params = self.get_dnac_params(self.params)
        log(str(dnac_params))
        self.dnac = DNACSDK(params=dnac_params)
        self.log = dnac_params.get("dnac_log")

        self.result = dict(changed=False, diff=[], response=[], warnings=[])

    def validate_input(self):
        temp_spec = dict(
            importImageDetails=dict(type='dict'),
            taggingDetails=dict(type='dict'),
            imageDistributionDetails=dict(type='dict'),
            imageActivationDetails=dict(type='dict'),
        )
        if self.config:
            msg = None
            # Validate site params
            valid_temp, invalid_params = validate_list_of_dicts(
                self.config, temp_spec
            )
            if invalid_params:
                msg = "Invalid parameters in playbook: {0}".format(
                    "\n".join(invalid_params)
                )
                self.module.fail_json(msg=msg)

            self.validated = valid_temp
            if self.log:
                log(str(valid_temp))
                log(str(self.validated))

    def get_dnac_params(self, params):
        dnac_params = dict(
            dnac_host=params.get("dnac_host"),
            dnac_port=params.get("dnac_port"),
            dnac_username=params.get("dnac_username"),
            dnac_password=params.get("dnac_password"),
            dnac_verify=params.get("dnac_verify"),
            dnac_debug=params.get("dnac_debug"),
            dnac_log=params.get("dnac_log")
        )
        return dnac_params

    def get_task_details(self, id):
        result = None
        response = self.dnac._exec(
            family="task",
            function='get_task_by_id',
            params={"task_id": id},
        )
        if self.log:
            log(str(response))

        if isinstance(response, dict):
            result = response.get("response")

        return result

    def site_exists(self):
        site_exists = False
        site_id = None
        response = None
        try:
            response = self.dnac._exec(
                family="sites",
                function='get_site',
                params={"name": self.want.get("site_name")},
            )
        except Exception as e:
            self.module.fail_json(msg="Site not found")

        if response:
            if self.log:
                log(str(response))

            site = response.get("response")
            site_id = site[0].get("id")
            site_exists = True

        return (site_exists, site_id)

    def get_image_id(self, name):
        # check if given image exists, if exists store image_id
        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function='get_software_image_details',
            params={"image_name": name},
        )

        if self.log:
            log(str(image_response))

        image_list = image_response.get("response")
        if (len(image_list) == 1):
            image_id = image_list[0].get("imageUuid")
            if self.log:
                log("Image Id: " + str(image_id))
        else:
            self.module.fail_json(msg="Image not found", response=image_response)

        return image_id

    def get_device_id(self, params):
        response = self.dnac._exec(
            family="devices",
            function='get_device_list',
            params=params,
        )
        if self.log:
            log(str(response))

        device_list = response.get("response")
        if (len(device_list) == 1):
            device_id = device_list[0].get("id")
            if self.log:
                log("Device Id: " + str(device_id))
        else:
            self.module.fail_json(msg="Device not found", response=response)

        return device_id

    def get_device_family_identifier(self, family_name):
        have = {}
        response = self.dnac._exec(
            family="software_image_management_swim",
            function='get_device_family_identifiers',
        )
        if self.log:
            log(str(response))
        device_family_db = response.get("response")
        if device_family_db:
            device_family_details = get_dict_result(device_family_db, 'deviceFamily', family_name)
            if device_family_details:
                device_family_identifier = device_family_details.get("deviceFamilyIdentifier")
                have["device_family_identifier"] = device_family_identifier
                if self.log:
                    log("Family device indentifier:" + str(device_family_identifier))
            else:
                self.module.fail_json(msg="Family Device Name not found", response=[])
            self.have.update(have)

    def get_have(self):
        if self.want.get("tagging_details"):
            have = {}
            tagging_details = self.want.get("tagging_details")
            if tagging_details.get("imageName"):
                image_id = self.get_image_id(tagging_details.get("imageName"))
                have["tagging_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["tagging_image_id"] = self.have.get("imported_image_id")

            else:
                self.module.fail_json(msg="Image details for tagging not provided", response=[])

            # check if given site exists, store siteid
            # if not then use global site
            site_name = tagging_details.get("siteName")
            if site_name:
                site_exists = False
                (site_exists, site_id) = self.site_exists()
                if site_exists:
                    have["site_id"] = site_id
                    if self.log:
                        log("Site Exists: " + str(site_exists) + "\n Site_id:" + str(site_id))
            else:
                # For global site, use -1 as siteId
                have["site_id"] = "-1"
                if self.log:
                    log("Site Name not given by user. Using global site.")

            self.have.update(have)
            # check if given device family name exists, store indentifier value
            family_name = tagging_details.get("deviceFamilyName")
            self.get_device_family_identifier(family_name)

        if self.want.get("distribution_details"):
            have = {}
            distribution_details = self.want.get("distribution_details")
            # check if image for distributon is available
            if distribution_details.get("imageName"):
                image_id = self.get_image_id(distribution_details.get("imageName"))
                have["distribution_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["distribution_image_id"] = self.have.get("imported_image_id")

            else:
                self.module.fail_json(msg="Image details for distribution not provided", response=[])

            device_params = dict(
                hostname=distribution_details.get("deviceHostname"),
                serial_number=distribution_details.get("deviceSerialNumber"),
                management_ip_address=distribution_details.get("deviceIpAddress"),
                mac_address=distribution_details.get("deviceMacAddress"),
            )
            device_id = self.get_device_id(device_params)
            have["distribution_device_id"] = device_id
            self.have.update(have)

        if self.want.get("activation_details"):
            have = {}
            activation_details = self.want.get("activation_details")
            # check if image for activation is available
            if activation_details.get("imageName"):
                image_id = self.get_image_id(activation_details.get("imageName"))
                have["activation_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["activation_image_id"] = self.have.get("imported_image_id")

            else:
                self.module.fail_json(msg="Image details for activation not provided", response=[])

            device_params = dict(
                hostname=activation_details.get("deviceHostname"),
                serial_number=activation_details.get("deviceSerialNumber"),
                management_ip_address=activation_details.get("deviceIpAddress"),
                mac_address=activation_details.get("deviceMacAddress"),
            )
            device_id = self.get_device_id(device_params)
            have["activation_device_id"] = device_id
            self.have.update(have)

    def get_want(self):
        want = {}
        for image in self.validated:
            if image.get("importImageDetails"):
                want["import_image"] = True
                want["import_type"] = image.get("importImageDetails").get("type").lower()
                if want["import_type"] == "url":
                    want["url_import_details"] = image.get("importImageDetails").get("urlDetails")
                elif want["import_type"] == "local":
                    want["local_import_details"] = image.get("importImageDetails").get("localImageDetails")
                else:
                    self.module.fail_json(msg="Incorrect import type. Supported Values: local or url")

            want["tagging_details"] = image.get("taggingDetails")
            want["distribution_details"] = image.get("imageDistributionDetails")
            want["activation_details"] = image.get("imageActivationDetails")

        self.want = want
        if self.log:
            log(str(self.want))

    def get_diff_import(self):
        if not self.want.get("import_image"):
            return

        if self.want.get("import_type") == "url":
            image_name = self.want.get("url_import_details").get("payload")[0].get("sourceURL")
            url_import_params = dict(
                payload=self.want.get("url_import_details").get("payload"),
                schedule_at=self.want.get("url_import_details").get("scheduleAt"),
                schedule_desc=self.want.get("url_import_details").get("scheduleDesc"),
                schedule_origin=self.want.get("url_import_details").get("scheduleOrigin"),
            )
            response = self.dnac._exec(
                family="software_image_management_swim",
                function='import_software_image_via_url',
                op_modifies=True,
                params=url_import_params,
            )
        else:
            image_name = self.want.get("local_import_details").get("filePath")
            local_import_params = dict(
                is_third_party=self.want.get("local_import_details").get("isThirdParty"),
                third_party_vendor=self.want.get("local_import_details").get("thirdPartyVendor"),
                third_party_image_family=self.want.get("local_import_details").get("thirdPartyImageFamily"),
                third_party_application_type=self.want.get("local_import_details").get("thirdPartyApplicationType"),
                file_path=self.want.get("local_import_details").get("filePath"),
            )
            response = self.dnac._exec(
                family="software_image_management_swim",
                function='import_local_software_image',
                op_modifies=True,
                params=local_import_params,
                file_paths=[('file_path', 'file')],
            )

        if self.log:
            log(str(response))

        task_details = {}
        task_id = response.get("response").get("taskId")
        while (True):
            task_details = self.get_task_details(task_id)
            if task_details and \
                    ("completed successfully" in task_details.get("progress").lower()):
                self.result['changed'] = True
                self.result['msg'] = "Image imported successfully"
                break

            if task_details and task_details.get("isError"):
                if "Image already exists" in task_details.get("failureReason"):
                    self.result['msg'] = "Image already exists."
                    break
                else:
                    self.module.fail_json(msg=task_details.get("failureReason"),
                                          response=task_details)

        self.result['response'] = task_details if task_details else response
        if not (self.want.get("tagging_details") or self.want.get("distribution_details")
                or self.want.get("activation_details")):
            return
        # Fetch image_id for the imported image for further use
        image_name = image_name.split('/')[-1]
        image_id = self.get_image_id(image_name)
        self.have["imported_image_id"] = image_id

    def get_diff_tagging(self):
        tagging_details = self.want.get("tagging_details")
        tag_image_golden = tagging_details.get("tagging")

        if tag_image_golden:
            image_params = dict(
                imageId=self.have.get("tagging_image_id"),
                siteId=self.have.get("site_id"),
                deviceFamilyIdentifier=self.have.get("device_family_identifier"),
                deviceRole=tagging_details.get("deviceRole")
            )
            if self.log:
                log("Image params for tagging image as golden:" + str(image_params))

            response = self.dnac._exec(
                family="software_image_management_swim",
                function='tag_as_golden_image',
                op_modifies=True,
                params=image_params
            )

        else:
            image_params = dict(
                image_id=self.have.get("tagging_image_id"),
                site_id=self.have.get("site_id"),
                device_family_identifier=self.have.get("device_family_identifier"),
                device_role=tagging_details.get("deviceRole")
            )
            if self.log:
                log("Image params for un-tagging image as golden:" + str(image_params))

            response = self.dnac._exec(
                family="software_image_management_swim",
                function='remove_golden_tag_for_image',
                op_modifies=True,
                params=image_params
            )

        if response:
            task_details = {}
            task_id = response.get("response").get("taskId")
            task_details = self.get_task_details(task_id)
            if not task_details.get("isError"):
                self.result['changed'] = True
                self.result['msg'] = task_details.get("progress")

            self.result['response'] = task_details if task_details else response

    def get_diff_distribution(self):
        distribution_details = self.want.get("distribution_details")
        distribution_params = dict(
            payload=[dict(
                deviceUuid=self.have.get("distribution_device_id"),
                imageUuid=self.have.get("distribution_image_id")
            )]
        )
        if self.log:
            log("Distribution Params: " + str(distribution_params))

        response = self.dnac._exec(
            family="software_image_management_swim",
            function='trigger_software_image_distribution',
            op_modifies=True,
            params=distribution_params,
        )
        if response:
            task_details = {}
            task_id = response.get("response").get("taskId")
            while (True):
                task_details = self.get_task_details(task_id)
                if not task_details.get("isError") and \
                        ("completed successfully" in task_details.get("progress")):
                    self.result['changed'] = True
                    self.result['msg'] = "Image Distributed Successfully"
                    break

                if task_details.get("isError"):
                    self.module.fail_json(msg="Image Distribution Failed",
                                          response=task_details)

            self.result['response'] = task_details if task_details else response

    def get_diff_activation(self):
        activation_details = self.want.get("activation_details")
        payload = [dict(
            activateLowerImageVersion=activation_details.get("activateLowerImageVersion"),
            deviceUpgradeMode=activation_details.get("deviceUpgradeMode"),
            distributeIfNeeded=activation_details.get("distributeIfNeeded"),
            deviceUuid=self.have.get("activation_device_id"),
            imageUuidList=[self.have.get("activation_image_id")]
        )]
        activation_params = dict(
            schedule_validate=activation_details.get("scehduleValidate"),
            payload=payload
        )
        if self.log:
            log("Activation Params: " + str(activation_params))

        response = self.dnac._exec(
            family="software_image_management_swim",
            function='trigger_software_image_activation',
            op_modifies=True,
            params=activation_params,
        )
        task_details = {}
        task_id = response.get("response").get("taskId")
        while (True):
            task_details = self.get_task_details(task_id)
            if not task_details.get("isError") and \
                    ("completed successfully" in task_details.get("progress")):
                self.result['changed'] = True
                self.result['msg'] = "Image activated successfully"
                break

            if task_details.get("isError"):
                self.module.fail_json(msg="Image Activation Failed",
                                          response=task_details)

        self.result['response'] = task_details if task_details else response

    def get_diff(self):
        if self.want.get("tagging_details"):
            self.get_diff_tagging()

        if self.want.get("distribution_details"):
            self.get_diff_distribution()

        if self.want.get("activation_details"):
            self.get_diff_activation()


def main():
    """ main entry point for module execution
    """

    element_spec = dict(
        dnac_host=dict(required=True, type='str'),
        dnac_port=dict(type='str', default='443'),
        dnac_username=dict(type='str', default='admin', aliases=["user"]),
        dnac_password=dict(type='str', no_log=True),
        dnac_verify=dict(type='bool', default='True'),
        dnac_version=dict(type="str", default="2.2.3.3"),
        dnac_debug=dict(type='bool', default=False),
        dnac_log=dict(type='bool', default=False),
        config=dict(required=True, type='list', elements='dict'),
        validate_response_schema=dict(type="bool", default=True),
    )

    module = AnsibleModule(argument_spec=element_spec,
                           supports_check_mode=False)

    dnac_swims = DnacSwims(module)
    dnac_swims.validate_input()
    dnac_swims.get_want()
    dnac_swims.get_diff_import()
    dnac_swims.get_have()
    dnac_swims.get_diff()

    module.exit_json(**dnac_swims.result)


if __name__ == '__main__':
    main()
