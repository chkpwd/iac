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
module: secrets_provider_vault
author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu VaultProvider secrets providers
description:
  - Create, update or delete a Sensu Go VaultProvider secrets provider.
  - For more information, refer to the Sensu Go documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/manage-secrets/secrets-providers/).
version_added: 1.6.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
options:
  address:
    description:
      - Address of the Vault server.
      - Required if I(state) is C(present).
    type: str
  token:
    description:
       - Authentication token to use with Vault.
       - Required if I(state) is C(present).
    type: str
  version:
    description:
      - Version of the Vault key/value store.
      - Please refer to U(https://www.vaultproject.io/docs/secrets/kv) for
          additional information.
      - Required if I(state) is C(present).
    type: str
    choices: [v1, v2]
  timeout:
    description:
      - Timeout (in seconds) for connection to Vault server.
    type: int
  max_retries:
    description:
      - Maximum number of times to retry failed connections to Vault server.
    type: int
  rate_limit:
    description:
      - Maximum number of secrets requests for per second.
    type: float
  burst_limit:
    description:
      - Maximum allowed number of secrets requests in a rate interval.
    type: int
  tls:
    description:
      - TLS configuration for establishing connection with Vault server.
    type: dict
    suboptions:
      ca_cert:
        description:
          - Path to the certificate file of the trusted certificate authority.
        type: str
      client_cert:
        description:
          - Path to the client certificate file.
        type: str
      client_key:
        description:
          - Path to the client key file.
        type: str
      cname:
        description:
          - Canonical name for the client.
        type: str

seealso:
  - module: sensu.sensu_go.secrets_provider_env
  - module: sensu.sensu_go.secrets_provider_info
  - module: sensu.sensu_go.secret
  - module: sensu.sensu_go.secret_info
'''

EXAMPLES = '''
- name: Create a vault secrets provider
  sensu.sensu_go.secrets_provider_vault:
    name: my-vault
    address: https://my-vault.com
    token: VAULT_TOKEN
    version: v1

- name: Delete a vault secrets provider
  sensu.sensu_go.secrets_provider_vault:
    name: my-vault
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu vault secrets provider.
  returned: success
  type: dict
  sample:
    metadata:
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
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "secrets/v1"


def do_differ(current, desired):
    if utils.do_differ_v1(current, desired, "client"):
        return True

    current_client = current["spec"]["client"]
    desired_client = desired["spec"]["client"]
    # Sensu Go API returns 'agent_address' field in the client spec,
    # but this field is not meant to be set via the providers API.
    if utils.do_differ(current_client, desired_client, "agent_address", "tls"):
        return True
    # Sensu Go API returns some extra fields in the tls spec.
    # We ignore them, as they are not meant to be set via the
    # providers API.
    return utils.do_differ(current_client["tls"], desired_client.get("tls") or {},
                           "insecure", "tls_server_name", "ca_path")


def _format_seconds(seconds):
    # Sensu API returns the configured timeout as a string, for instance
    # 30 -> '30s', 60-> '1m0s', 3600 -> '1h0m0s'.
    h, r = divmod(seconds, 3600)
    m, s = divmod(r, 60)
    if h:
        return "{0}h{1}m{2}s".format(h, m, s)
    if m:
        return "{0}m{1}s".format(m, s)
    return "{0}s".format(seconds)


def build_vault_provider_spec(params):
    if params["state"] == "absent":
        return {}

    client = arguments.get_spec_payload(
        params, "address", "token", "version", "max_retries",
    )
    if params.get("tls"):
        client["tls"] = arguments.get_spec_payload(
            params["tls"], "ca_cert", "client_cert", "client_key", "cname",
        )
    if params.get("timeout"):
        client["timeout"] = _format_seconds(params["timeout"])

    if params.get("rate_limit") or params.get("burst_limit"):
        client["rate_limiter"] = arguments.get_renamed_spec_payload(
            params, dict(
                rate_limit="limit",
                burst_limit="burst",
            )
        )

    return dict(client=client)


def main():
    required_if = [
        ("state", "present", ["address", "token", "version"])
    ]

    module = AnsibleModule(
        supports_check_mode=True,
        required_if=required_if,
        argument_spec=dict(
            arguments.get_spec(
                "auth", "name", "state",
            ),
            address=dict(),
            token=dict(no_log=True),
            version=dict(
                choices=["v1", "v2"],
            ),
            timeout=dict(
                type="int",
            ),
            max_retries=dict(
                type="int",
            ),
            rate_limit=dict(
                type="float",
            ),
            burst_limit=dict(
                type="int",
            ),
            tls=dict(
                type="dict",
                options=dict(
                    ca_cert=dict(),
                    cname=dict(),
                    client_cert=dict(),
                    client_key=dict(no_log=False),
                )
            )
        )
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, None, 'providers', module.params['name']
    )

    payload = dict(
        type="VaultProvider",
        api_version=API_VERSION,
        metadata=dict(name=module.params["name"]),
        spec=build_vault_provider_spec(module.params)
    )

    try:
        changed, vault_provider = utils.sync_v1(
            module.params['state'], client, path, payload, module.check_mode, do_differ
        )
        module.exit_json(changed=changed, object=vault_provider)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
