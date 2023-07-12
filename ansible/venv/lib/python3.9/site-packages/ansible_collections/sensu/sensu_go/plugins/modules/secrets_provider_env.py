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

DOCUMENTATION = '''
module: secrets_provider_env
author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu Env secrets provider
description:
  - Create or delete a Sensu Go Env secrets provider.
  - The module operates on a secrets provider named C(env).
  - For more information, refer to the Sensu Go documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/manage-secrets/secrets-providers/).
version_added: 1.6.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.secrets_provider_vault
  - module: sensu.sensu_go.secrets_provider_info
  - module: sensu.sensu_go.secret
  - module: sensu.sensu_go.secret_info
'''

EXAMPLES = '''
- name: Create the env secrets provider
  sensu.sensu_go.secrets_provider_env:

- name: Delete the env secrets provider
  sensu.sensu_go.secrets_provider_env:
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu Env secrets provider.
  returned: success
  type: dict
  sample:
    - metadata:
        name: env
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "secrets/v1"


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "state",
            ),
        )
    )
    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, None, 'providers', 'env'
    )
    payload = dict(
        type="Env",
        api_version=API_VERSION,
        metadata=dict(name='env'),
        spec={},
    )

    try:
        changed, env_provider = utils.sync_v1(
            module.params['state'], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=env_provider)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
