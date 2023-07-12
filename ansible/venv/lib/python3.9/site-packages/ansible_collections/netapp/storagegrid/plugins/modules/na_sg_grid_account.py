#!/usr/bin/python

# (c) 2020, NetApp Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""NetApp StorageGRID - Manage Accounts"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type


ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}


DOCUMENTATION = """
module: na_sg_grid_account
short_description: NetApp StorageGRID manage accounts.
extends_documentation_fragment:
    - netapp.storagegrid.netapp.sg
version_added: '20.6.0'
author: NetApp Ansible Team (@joshedmonds) <ng-ansibleteam@netapp.com>
description:
- Create, Update, Delete Tenant Accounts on NetApp StorageGRID.
options:
  state:
    description:
    - Whether the specified account should exist or not.
    - Required for all operations.
    type: str
    choices: ['present', 'absent']
    default: present
  name:
    description:
    - Name of the tenant.
    - Required for create or modify operation.
    type: str
  account_id:
    description:
    - Account Id of the tenant.
    - May be used for modify or delete operation.
    type: str
  protocol:
    description:
    - Object Storage protocol used by the tenancy.
    - Required for create operation.
    type: str
    choices: ['s3', 'swift']
  management:
    description:
    - Whether the tenant can login to the StorageGRID tenant portal.
    type: bool
    default: true
  use_own_identity_source:
    description:
    - Whether the tenant account should configure its own identity source.
    type: bool
  allow_platform_services:
    description:
    - Allows tenant to use platform services features such as CloudMirror.
    type: bool
  root_access_group:
    description:
    - Existing federated group to have initial Root Access permissions for the tenant.
    - Must begin with C(federated-group/)
    type: str
    version_added: 20.11.0
  quota_size:
    description:
    - Quota to apply to the tenant specified in I(quota_size_unit).
    - If you intend to have no limits, assign C(0).
    type: int
    default: 0
  quota_size_unit:
    description:
    - The unit used to interpret the size parameter.
    choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
    type: str
    default: 'gb'
  password:
    description:
    - Root password for tenant account.
    - Requires root privilege.
    type: str
  update_password:
    description:
    - Choose when to update the password.
    - When set to C(always), the password will always be updated.
    - When set to C(on_create) the password will only be set upon a new user creation.
    default: on_create
    choices:
    - on_create
    - always
    type: str
"""

EXAMPLES = """
  - name: create a tenant account
    netapp.storagegrid.na_sg_grid_account:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: present
      name: storagegrid-tenant-1
      protocol: s3
      management: true
      use_own_identity_source: false
      allow_platform_services: false
      password: "tenant-password"
      quota_size: 0

  - name: update a tenant account
    netapp.storagegrid.na_sg_grid_account:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: present
      name: storagegrid-tenant-1
      protocol: s3
      management: true
      use_own_identity_source: false
      allow_platform_services: true
      password: "tenant-password"
      quota_size: 10240

  - name: delete a tenant account
    netapp.storagegrid.na_sg_grid_account:
      api_url: "https://<storagegrid-endpoint-url>"
      auth_token: "storagegrid-auth-token"
      validate_certs: false
      state: absent
      name: storagegrid-tenant-1
      protocol: s3
"""

RETURN = """
resp:
    description: Returns information about the StorageGRID tenant account.
    returned: success
    type: dict
    sample: {
        "name": "Example Account",
        "capabilities": ["management", "s3"],
        "policy": {
            "useAccountIdentitySource": true,
            "allowPlatformServices": false,
            "quotaObjectBytes": 100000000000
        },
        "id": "12345678901234567890"
    }
"""

import ansible_collections.netapp.storagegrid.plugins.module_utils.netapp as netapp_utils
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp_module import (
    NetAppModule,
)
from ansible_collections.netapp.storagegrid.plugins.module_utils.netapp import (
    SGRestAPI,
)


class SgGridAccount(object):
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
                name=dict(required=False, type="str"),
                account_id=dict(required=False, type="str"),
                protocol=dict(required=False, choices=["s3", "swift"]),
                management=dict(required=False, type="bool", default=True),
                use_own_identity_source=dict(required=False, type="bool"),
                allow_platform_services=dict(required=False, type="bool"),
                root_access_group=dict(required=False, type="str"),
                quota_size=dict(required=False, type="int", default=0),
                quota_size_unit=dict(
                    default="gb",
                    choices=[
                        "bytes",
                        "b",
                        "kb",
                        "mb",
                        "gb",
                        "tb",
                        "pb",
                        "eb",
                        "zb",
                        "yb",
                    ],
                    type="str",
                ),
                password=dict(required=False, type="str", no_log=True),
                update_password=dict(
                    default="on_create", choices=["on_create", "always"]
                ),
            )
        )

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                (
                    "state",
                    "present",
                    [
                        "name",
                        "protocol",
                        "use_own_identity_source",
                        "allow_platform_services",
                    ],
                )
            ],
            supports_check_mode=True,
        )

        self.na_helper = NetAppModule()

        # set up state variables
        self.parameters = self.na_helper.set_parameters(self.module.params)
        # Calling generic SG rest_api class
        self.rest_api = SGRestAPI(self.module)

        # Checking for the parameters passed and create new parameters list
        self.data = {}
        self.data["name"] = self.parameters["name"]
        self.data["capabilities"] = [self.parameters["protocol"]]

        if self.parameters.get("password") is not None:
            self.data["password"] = self.parameters["password"]

        # Append "management" to the capability list only if parameter is True
        if self.parameters.get("management"):
            self.data["capabilities"].append("management")

        self.data["policy"] = {}

        if "use_own_identity_source" in self.parameters:
            self.data["policy"]["useAccountIdentitySource"] = self.parameters[
                "use_own_identity_source"
            ]

        if "allow_platform_services" in self.parameters:
            self.data["policy"]["allowPlatformServices"] = self.parameters[
                "allow_platform_services"
            ]

        if self.parameters.get("root_access_group") is not None:
            self.data["grantRootAccessToGroup"] = self.parameters["root_access_group"]

        if self.parameters["quota_size"] > 0:
            self.parameters["quota_size"] = (
                self.parameters["quota_size"]
                * netapp_utils.POW2_BYTE_MAP[
                    self.parameters["quota_size_unit"]
                ]
            )
            self.data["policy"]["quotaObjectBytes"] = self.parameters[
                "quota_size"
            ]
        elif self.parameters["quota_size"] == 0:
            self.data["policy"]["quotaObjectBytes"] = None

        self.pw_change = {}
        if self.parameters.get("password") is not None:
            self.pw_change["password"] = self.parameters["password"]

    def get_tenant_account_id(self):
        # Check if tenant account exists
        # Return tenant account info if found, or None
        api = "api/v3/grid/accounts?limit=350"

        list_accounts, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)

        for account in list_accounts.get("data"):
            if account["name"] == self.parameters["name"]:
                return account["id"]

        return None

    def get_tenant_account(self, account_id):
        api = "api/v3/grid/accounts/%s" % account_id
        account, error = self.rest_api.get(api)

        if error:
            self.module.fail_json(msg=error)
        else:
            return account["data"]
        return None

    def create_tenant_account(self):
        api = "api/v3/grid/accounts"

        response, error = self.rest_api.post(api, self.data)

        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def delete_tenant_account(self, account_id):
        api = "api/v3/grid/accounts/" + account_id

        self.data = None
        response, error = self.rest_api.delete(api, self.data)
        if error:
            self.module.fail_json(msg=error)

    def update_tenant_account(self, account_id):
        api = "api/v3/grid/accounts/" + account_id

        if "password" in self.data:
            del self.data["password"]

        if "grantRootAccessToGroup" in self.data:
            del self.data["grantRootAccessToGroup"]

        response, error = self.rest_api.put(api, self.data)
        if error:
            self.module.fail_json(msg=error)

        return response["data"]

    def set_tenant_root_password(self, account_id):
        api = "api/v3/grid/accounts/%s/change-password" % account_id
        response, error = self.rest_api.post(api, self.pw_change)

        if error:
            self.module.fail_json(msg=error["text"])

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        tenant_account = None

        if self.parameters.get("account_id"):
            tenant_account = self.get_tenant_account(
                self.parameters["account_id"]
            )

        else:
            tenant_account_id = self.get_tenant_account_id()
            if tenant_account_id:
                tenant_account = self.get_tenant_account(tenant_account_id)

        cd_action = self.na_helper.get_cd_action(
            tenant_account, self.parameters
        )

        if cd_action is None and self.parameters["state"] == "present":
            # let's see if we need to update parameters
            update = False

            capability_diff = [
                i
                for i in self.data["capabilities"]
                + tenant_account["capabilities"]
                if i not in self.data["capabilities"]
                or i not in tenant_account["capabilities"]
            ]

            if self.parameters["quota_size"] > 0:
                if (
                    tenant_account["policy"]["quotaObjectBytes"]
                    != self.parameters["quota_size"]
                ):
                    update = True
            elif (
                self.parameters["quota_size"] == 0
                and tenant_account["policy"]["quotaObjectBytes"] is not None
            ):
                update = True

            if (
                "use_own_identity_source" in self.parameters
                and tenant_account["policy"]["useAccountIdentitySource"]
                != self.parameters["use_own_identity_source"]
            ):
                update = True

            elif (
                "allow_platform_services" in self.parameters
                and tenant_account["policy"]["allowPlatformServices"]
                != self.parameters["allow_platform_services"]
            ):
                update = True

            elif capability_diff:
                update = True

            if update:
                self.na_helper.changed = True

        result_message = ""
        resp_data = tenant_account
        if self.na_helper.changed:
            if self.module.check_mode:
                pass
            else:
                if cd_action == "delete":
                    self.delete_tenant_account(tenant_account["id"])
                    result_message = "Tenant Account deleted"
                    resp_data = None

                elif cd_action == "create":
                    resp_data = self.create_tenant_account()
                    result_message = "Tenant Account created"

                else:
                    resp_data = self.update_tenant_account(tenant_account["id"])
                    result_message = "Tenant Account updated"

        # If a password has been set
        if self.pw_change:
            if self.module.check_mode:
                pass
            else:
                # Only update the password if update_password is always
                # On a create action, the password is set directly by the POST /grid/accounts method
                if self.parameters["update_password"] == "always" and cd_action != "create":
                    self.set_tenant_root_password(tenant_account["id"])
                    self.na_helper.changed = True

                    results = [result_message, "Tenant Account root password updated"]
                    result_message = "; ".join(filter(None, results))

        self.module.exit_json(
            changed=self.na_helper.changed, msg=result_message, resp=resp_data
        )


def main():
    """
    Main function
    """
    na_sg_grid_account = SgGridAccount()
    na_sg_grid_account.apply()


if __name__ == "__main__":
    main()
