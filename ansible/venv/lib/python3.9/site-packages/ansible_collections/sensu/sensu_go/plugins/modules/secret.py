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
module: secret
author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu Go secrets
description:
  - Create, update or delete Sensu secret.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/manage-secrets/secrets/).
version_added: 1.6.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.namespace
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.secret_info
  - module: sensu.sensu_go.secrets_provider_env
  - module: sensu.sensu_go.secrets_provider_vault
  - module: sensu.sensu_go.secrets_provider_info
options:
  provider:
    description:
      - Name of the secrets provider that backs the secret value.
      - Required if I(state) is C(present).
    type: str
  id:
    description:
      - Secret's id in the provider store.
      - Required if I(state) is C(present).
    type: str
"""

EXAMPLES = """
- name: Create an environment varibale-backed secret
  sensu.sensu_go.secret:
    name: env_secret
    provider: env
    id: MY_ENV_VARIABLE

- name: Create a HashiCorp Vault-backed secret
  sensu.sensu_go.secret:
    name: hashi_valut_secret
    provider: vault
    id: secret/store#name

- name: Delete a secret
  sensu.sensu_go.secret:
    name: my_secret
    state: absent
"""

RETURN = """
object:
  description: Object representing Sensu secret.
  returned: success
  type: dict
  sample:
    metadata:
      name: sensu-ansible
      namespace: default
    id: 'secret/database#password'
    provider: vault
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "secrets/v1"


def main():
    required_if = [
        ("state", "present", ["provider", "id"])
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name", "state", "namespace"),
            provider=dict(type="str"),
            id=dict(type="str"),
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, module.params["namespace"], "secrets",
        module.params["name"],
    )
    payload = dict(
        type="Secret",
        api_version=API_VERSION,
        metadata=dict(
            name=module.params["name"],
            namespace=module.params["namespace"],
        ),
        spec=arguments.get_spec_payload(module.params, "provider", "id"),
    )
    try:
        changed, secret = utils.sync_v1(
            module.params["state"], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=secret)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
