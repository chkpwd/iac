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
module: secret_info
author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)
short_description: List available Sensu Go secrets
description:
  - Retrieve information about Sensu Go secrets.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/manage-secrets/secrets/).
version_added: 1.6.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.secret
  - module: sensu.sensu_go.secrets_provider_env
  - module: sensu.sensu_go.secrets_provider_vault
  - module: sensu.sensu_go.secrets_provider_info
"""

EXAMPLES = """
- name: List all Sensu Go secrets
  sensu.sensu_go.secret_info:
  register: result

- name: Retrieve the selected Sensu Go secret
  sensu.sensu_go.secret_info:
    name: my-secret
  register: result

- name: Do something with result
  ansible.builtin.debug:
    msg: "{{ result.objects.0.id }}"
"""

RETURN = """
objects:
  description: List of Sensu Go secrets.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: sensu-ansible-token
        namespace: default
      id: ANSIBLE_TOKEN
      provider: env
    - metadata:
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
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            name=dict(),  # Name is not required in info modules.
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, module.params["namespace"], "secrets",
        module.params["name"],
    )

    try:
        secrets = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    # We simulate the behavior of v2 API here and only return the spec.
    module.exit_json(changed=False, objects=[
        utils.convert_v1_to_v2_response(s) for s in secrets
    ])


if __name__ == "__main__":
    main()
