#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Buckets"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_org_container
short_description: Manage buckets on StorageGRID.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create S3 buckets on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified bucket should exist or not.
    type: str
    choices: ['present', 'absent']
    default: present
  name:
    description:
    - Name of the bucket.
    required: true
    type: str
  region:
    description:
    - Set a region for the bucket.
    type: str
  compliance:
    description:
    - Configure compliance settings for an S3 bucket.
    - Cannot be specified along with I(s3_object_lock_enabled).
    type: dict
    suboptions:
      auto_delete:
        description:
        - If enabled, objects will be deleted automatically when its retention period expires, unless the bucket is under a legal hold.
        type: bool
      legal_hold:
        description:
        - If enabled, objects in this bucket cannot be deleted, even if their retention period has expired.
        type: bool
      retention_period_minutes:
        description:
        - specify the length of the retention period for objects added to this bucket, in minutes.
        type: int
  s3_object_lock_enabled:
    description:
    - Enable S3 Object Lock on the bucket.
    - S3 Object Lock requires StorageGRID 11.5 or greater.
    type: bool
    version_added: '21.9.0'
  bucket_versioning_enabled:
    description:
    - Enable versioning on the bucket.
    - This API requires StorageGRID 11.6 or greater.
    type: bool
    version_added: '21.11.0'
"""

EXAMPLES = """
  - name: create a s3 bucket
    netapp.storagegrid.na_sg_org_container:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: present
      name: ansiblebucket1

  - name: delete a s3 bucket
    netapp.storagegrid.na_sg_org_container:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: absent
      name: ansiblebucket1

  - name: create a s3 bucket with Object Lock
    netapp.storagegrid.na_sg_org_container:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: present
      name: objectlock-bucket1
      s3_object_lock_enabled: true

  - name: create a s3 bucket with versioning enabled
    netapp.storagegrid.na_sg_org_container:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: present
      name: ansiblebucket1
      bucket_versioning_enabled: true
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID bucket.
    returned: always
    type: dict
    sample: {
        "name": "example-bucket",
        "creationTime": "2021-01-01T00:00:00.000Z",
        "region": "us-east-1",
        "compliance": {
            "autoDelete": false,
            "legalHold": false,
            "retentionPeriodMinutes": 2629800
        },
        "s3ObjectLock": {
            "enabled": false
        }
    }
"""

import json

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import SGRestAPI


class SgOrgContainer(object):
    """
    Create, modify and delete StorageGRID Tenant Account
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_storagegrid_host_argument_spec()
        self.argument_spec.update(
            dict(
                state=dict(required=False, type="str", choices=["present", "absent"], default="present"),
                name=dict(required=True, type="str"),
                region=dict(required=False, type="str"),
                compliance=dict(
                    required=False,
                    type="dict",
                    options=dict(
                        auto_delete=dict(required=False, type="bool"),
                        legal_hold=dict(required=False, type="bool"),
                        retention_period_minutes=dict(required=False, type="int"),
                    ),
                ),
                s3_object_lock_enabled=dict(required=False, type="bool"),
                bucket_versioning_enabled=dict(required=False, type="bool"),
            )
        )
        parameter_map = {
            "auto_delete": "autoDelete",
            "legal_hold": "legalHold",
            "retention_period_minutes": "retentionPeriodMinutes",
        }
        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            mutually_exclusive=[("compliance", "s3_object_lock_enabled")],
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)
        # Get API version
        self.rest_api.get_sg_product_version(api_root="org")

        # Checking for the parameters passed and create new parameters list

        self.data_versioning = {}
        self.data_versioning["versioningSuspended"] = True

        self.data = {}
        self.data["name"] = self.parameters["name"]
        self.data["region"] = self.parameters.get("region")
        if self.parameters.get("compliance"):
            self.data["compliance"] = dict(
                (parameter_map[k], v) for (k, v) in self.parameters["compliance"].items() if v is not None
            )

        if self.parameters.get("s3_object_lock_enabled") is not None:
            self.rest_api.fail_if_not_sg_minimum_version("S3 Object Lock", 11, 5)
            self.data["s3ObjectLock"] = dict(enabled=self.parameters["s3_object_lock_enabled"])

        if self.parameters.get("bucket_versioning_enabled") is not None:
            self.rest_api.fail_if_not_sg_minimum_version("Bucket versioning configuration", 11, 6)
            self.data_versioning["versioningEnabled"] = self.parameters["bucket_versioning_enabled"]
            if self.data_versioning["versioningEnabled"]:
                self.data_versioning["versioningSuspended"] = False

    def get_org_container(self):
        # Check if bucket/container exists
        # Return info if found, or None

        params = {"include": "compliance,region"}
        response, error = self.rest_api.get("api/v3/org/containers", params=params)

        if error:
            self.module.fail_json(msg=error)

        for container in response["data"]:
            if container["name"] == self.parameters["name"]:
                return container

        return None

    def create_org_container(self):
        api = "api/v3/org/containers"

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def get_org_container_versioning(self):
        api = "api/v3/org/containers/%s/versioning" % self.parameters["name"]
        response, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def update_org_container_versioning(self):
        api = "api/v3/org/containers/%s/versioning" % self.parameters["name"]

        response, error = self.rest_api.put(api, self.data_versioning)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def fail_if_global_object_lock_disabled(self):
        api = "api/v3/org/compliance-global"

        response, error = self.rest_api.get(api)
        if error:
            self.module.fail_json(msg=error)

        if not response["data"]["complianceEnabled"]:
            self.module.fail_json(msg="Error: Global S3 Object Lock setting is not enabled.")

    def update_org_container_compliance(self):
        api = "api/v3/org/containers/%s/compliance" % self.parameters["name"]

        response, error = self.rest_api.put(api, self.data["compliance"])
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_org_container(self):
        api = "api/v3/org/containers/%s" % self.parameters["name"]

        response, error = self.rest_api.delete(api, None)
        if error:
            self.module.fail_json(msg=error["text"])

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """
        versioning_config = None
        update_versioning = False

        org_container = self.get_org_container()

        if org_container and self.parameters.get("bucket_versioning_enabled") is not None:
            versioning_config = self.get_org_container_versioning()

        cd_action = self.na_helper.get_cd_action(org_container, self.parameters)

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update_compliance = False

            if self.parameters.get("compliance") and org_container.get("compliance") != self.data["compliance"]:
                update_compliance = True
                self.na_helper.changed = True

            if (
                versioning_config
                and versioning_config["versioningEnabled"] != self.data_versioning["versioningEnabled"]
            ):
                update_versioning = True
                self.na_helper.changed = True

        result_message = ""
        resp_data = org_container
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_org_container()
                    resp_data = None
                    result_message = "Org Container deleted"

                elif cd_action == "create":
                    if self.parameters.get("s3_object_lock_enabled"):  # if it is set and true
                        self.fail_if_global_object_lock_disabled()

                    resp_data = self.create_org_container()

                    if self.parameters.get("bucket_versioning_enabled") is not None:
                        self.update_org_container_versioning()
                    result_message = "Org Container created"

                else:
                    if update_compliance:
                        resp_data = self.update_org_container_compliance()
                    if update_versioning:
                        self.update_org_container_versioning()
                    result_message = "Org Container updated"

        self.module.exit_json(changed=self.na_helper.changed, msg=result_message, resp=resp_data)


def main():
    """
    Main function
    """
    na_sg_org_container = SgOrgContainer()
    na_sg_org_container.apply()


if __name__ == "__main__":
    main()
