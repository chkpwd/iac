#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["stableinterface"],
    "supported_by": "certified",
}

DOCUMENTATION = """
module: oidc_auth_provider

author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)

short_description: Manage Sensu OIDC authentication provider

description:
  - Create, update or delete a Sensu Go OIDC authentication provider.
  - For more information, refer to the Sensu Go documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/control-access/oidc-auth/).

version_added: 1.10.0

extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state

options:
  additional_scopes:
    description:
      - Scopes to include in the claims.
    type: list
    elements: str
    default: openid
  client_id:
    description:
      - The OIDC provider application Client ID.
      - Required if I(state) is C(present).
    type: str
  client_secret:
    description:
      - The OIDC provider application Client Secret.
      - Required if I(state) is C(present).
    type: str
  disable_offline_access:
    description:
      - If C(true), the OIDC provider cannot include the offline_access scope
       in the authentication request. Otherwise, C(false).
    type: bool
    default: false
  redirect_uri:
    description:
      - Redirect URL to provide to the OIDC provider.
    type: str
  server:
    description:
      - The location of the OIDC server you wish to authenticate against.
      - Required if I(state) is C(present).
    type: str
  groups_claim:
    description:
      - The claim to use to form the associated RBAC groups.
    type: str
  groups_prefix:
    description:
      - The prefix added to all OIDC groups.
    type: str
  username_claim:
    description:
      - The claim to use to form the final RBAC user name.
      - Required if I(state) is C(present).
    type: str
  username_prefix:
    description:
      - The prefix added to all OIDC usernames.
    type: str

seealso:
  - module: sensu.sensu_go.auth_provider_info
  - module: sensu.sensu_go.ldap_auth_provider
  - module: sensu.sensu_go.ad_auth_provider

notes:
  - Supported only on Sensu Go versions >= 6.
"""

EXAMPLES = """
- name: Create a OIDC auth provider
  sensu.sensu_go.oidc_auth_provider:
    state: present
    name: oidc_name
    additional_scopes:
        - groups
        - email
    client_id: a8e43af034e7f2608780
    client_secret: b63968394be6ed2edb61c93847ee792f31bf6216
    disable_offline_access: false
    redirect_uri: http://127.0.0.1:8080/api/enterprise/authentication/v2/oidc/callback
    server: https://oidc.example.com:9031
    groups_claim: groups
    groups_prefix: 'oidc:'
    username_claim: email
    username_prefix: 'oidc:'

- name: Delete a OIDC auth provider
  sensu.sensu_go.oidc_auth_provider:
    name: oidc_name
    state: absent
"""

RETURN = """
object:
  description: Object representing Sensu OIDC authentication provider.
  returned: success
  type: dict
  sample:
    metadata:
      name: 'oidc_name'
      created_by: 'admin'
    additional_scopes:
        - 'groups'
        - 'email'
    client_id: 'a8e43af034e7f2608780'
    disable_offline_access: false
    redirect_uri: 'http://sensu-backend.example.com:8080/api/enterprise/authentication/v2/oidc/callback'
    server: 'https://oidc.example.com:9031'
    groups_claim: 'groups'
    groups_prefix: 'oidc:'
    username_claim: 'email'
    username_prefix: 'oidc:'
"""


from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "authentication/v2"


def remove_item(result):
    if result and 'client_secret' in result:
        del result['client_secret']

    return result


def main():
    required_if = [
        ("state", "present", ["client_id", "client_secret", "server", "username_claim"])
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec(
                "auth",
                "name",
                "state",
            ),
            additional_scopes=dict(
                type="list",
                elements="str",
                default="openid",
            ),
            client_id=dict(
                type="str",
            ),
            client_secret=dict(
                type="str",
                no_log=True,
            ),
            disable_offline_access=dict(
                type="bool",
                default=False,
            ),
            redirect_uri=dict(
                type="str",
            ),
            server=dict(
                type="str",
            ),
            groups_claim=dict(
                type="str",
            ),
            groups_prefix=dict(
                type="str",
            ),
            username_claim=dict(
                type="str",
            ),
            username_prefix=dict(
                type="str",
            ),
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, None, "authproviders", module.params["name"]
    )

    payload = dict(
        type="oidc",
        api_version=API_VERSION,
        metadata=dict(name=module.params["name"]),
        spec=arguments.get_spec_payload(
            module.params,
            "additional_scopes",
            "client_id",
            "client_secret",
            "disable_offline_access",
            "redirect_uri",
            "server",
            "groups_claim",
            "groups_prefix",
            "username_claim",
            "username_prefix",
        ),
    )

    try:
        changed, oidc_provider = utils.sync_v1(
            module.params["state"], client, path, payload, module.check_mode
        )
        module.exit_json(
            changed=changed, object=remove_item(oidc_provider)
        )
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
