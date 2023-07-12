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
module: auth_provider_info

author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)

short_description: List Sensu authentication providers

description:
  - Retrieve information about Sensu Go authentication providers.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/control-access/).

version_added: 1.10.0

extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info

seealso:
  - module: sensu.sensu_go.ad_auth_provider
  - module: sensu.sensu_go.ldap_auth_provider
  - module: sensu.sensu_go.oidc_auth_provider
"""

EXAMPLES = """
- name: List all Sensu authentication providers
  sensu.sensu_go.auth_provider_info:
  register: result

- name: List the selected Sensu authentication provider
  sensu.sensu_go.auth_provider_info:
    name: my_auth_provider
  register: result

- name: Do something with result
  ansible.builtin.debug:
    msg: "{{ result.objects.0.metadata.name }}"
"""

RETURN = """
objects:
  description: List of Sensu authentication providers.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: 'openldap'
      groups_prefix: ''
      servers:
        binding:
          user_dn: 'cn=binder,dc=acme,dc=org'
        client_cert_file: ''
        client_key_file: ''
        default_upn_domain: ''
        group_search:
          attribute: 'member'
          base_dn: 'dc=acme,dc=org'
          name_attribute: 'cn'
          object_class: 'groupOfNames'
        host: '127.0.0.1'
        insecure: false
        port: 636
        security: 'tls'
        trusted_ca_file: ''
        user_search:
          attribute: 'uid'
          base_dn: 'dc=acme,dc=org'
          name_attribute: 'cn'
          object_class: 'person'
      username_prefix: ''
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "authentication/v2"


def remove_item(result):
    for server in result.get("servers", []):
        if server["binding"] and "password" in server["binding"]:
            del server["binding"]["password"]

    if "client_secret" in result:
        del result["client_secret"]

    return result


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth"),
            name=dict(),  # Name is not required in info modules.
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP,
        API_VERSION,
        None,
        "authproviders",
        module.params["name"],
    )

    try:
        providers = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    # We simulate the behavior of v2 API here and only return the spec.
    module.exit_json(
        changed=False,
        objects=[remove_item(utils.convert_v1_to_v2_response(p)) for p in providers],
    )


if __name__ == "__main__":
    main()
