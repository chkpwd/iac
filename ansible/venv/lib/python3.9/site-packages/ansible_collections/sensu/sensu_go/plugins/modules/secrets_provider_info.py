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
module: secrets_provider_info
author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu secrets providers
description:
  - Retrieve information about Sensu Go secrets providers.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/manage-secrets/secrets-providers/).
version_added: 1.6.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
seealso:
  - module: sensu.sensu_go.secrets_provider_env
  - module: sensu.sensu_go.secrets_provider_vault
  - module: sensu.sensu_go.secret
  - module: sensu.sensu_go.secret_info
"""

EXAMPLES = """
- name: List all Sensu secrets providers
  sensu.sensu_go.secrets_provider_info:
  register: result

- name: List the selected Sensu secrets provider
  sensu.sensu_go.secrets_provider_info:
    name: my_provider
  register: result

- name: Do something with result
  ansible.builtin.debug:
    msg: "{{ result.objects.0.metadata.name }}"
"""

RETURN = """
objects:
  description: List of Sensu secrets providers.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: vault
      client:
        address: https://vaultserver.example.com:8200
        token: VAULT_TOKEN
        version: v1
        tls:
          ca_cert: "/etc/ssl/certs/vault_ca_cert.pem"
        max_retries: 2
        timeout: 20s
        rate_limiter:
          limit: 10
          burst: 100
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "secrets/v1"


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
        API_GROUP, API_VERSION, None, "providers", module.params["name"],
    )

    try:
        providers = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    # We simulate the behavior of v2 API here and only return the spec.
    module.exit_json(changed=False, objects=[
        utils.convert_v1_to_v2_response(p) for p in providers
    ])


if __name__ == "__main__":
    main()
