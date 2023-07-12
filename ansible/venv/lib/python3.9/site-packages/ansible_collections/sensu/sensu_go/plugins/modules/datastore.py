#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
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
module: datastore
author:
  - Manca Bizjak (@mancabizjak)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu external datastore providers
description:
  - Add or remove external datastore provider.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/datastore/).
version_added: 1.1.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.datastore_info
options:
  dsn:
    description:
      - Attribute that specifies the data source names as a URL or
        PostgreSQL connection string. See the PostgreSQL docs for more
        information about connection strings.
    type: str
  pool_size:
    description:
      - The maximum number of connections to hold in the PostgreSQL connection
        pool.
    type: int
notes:
  - Currently, only one external datastore can be active at a time. The module
    will fail to perform its operation if this would break that invariant.
'''

EXAMPLES = '''
- name: Add external datastore
  sensu.sensu_go.datastore:
    name: my-postgres
    dsn: postgresql://user:secret@host:port/dbname

- name: Remove external datastore
  sensu.sensu_go.datastore:
    name: my-postgres
    state: absent
'''

RETURN = '''
object:
  description: Object representing external datastore provider.
  returned: success
  type: dict
  sample:
    metadata:
      name: my-postgres
    batch_buffer: 0
    batch_size: 1
    batch_workers: 0
    dsn: "postgresql://user:secret@host:port/dbname"
    max_conn_lifetime: 5m
    max_idle_conns: 2
    pool_size: 20
    strict: true
    enable_round_robin: true
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "store/v1"


def _get(client, path):
    return utils.convert_v1_to_v2_response(utils.get(client, path))


def sync(state, client, list_path, resource_path, payload, check_mode):
    datastore = _get(client, resource_path)

    # When we are deleting stores, we do not care if there is more than one
    # datastore present. We just make sure the currently manipulated store is
    # gone. This makes our module useful in "let us clean up the mess"
    # scenarios.
    if state == "absent" and datastore is None:
        return False, None

    if state == "absent":
        if not check_mode:
            utils.delete(client, resource_path)
        return True, None

    # If the store exists, update it and ignore the fact that there might be
    # more than one present.
    if datastore:
        if utils.do_differ(datastore, payload["spec"]):
            if check_mode:
                return True, payload["spec"]
            utils.put(client, resource_path, payload)
            return True, _get(client, resource_path)
        return False, datastore

    # When adding a new datastore, we first make sure there is no other
    # datastore present because we do not want to be the ones who brought
    # backends into an inconsistent state.
    if utils.get(client, list_path):
        raise errors.Error("Some other external datastore is already active.")

    if check_mode:
        return True, payload["spec"]
    utils.put(client, resource_path, payload)
    return True, _get(client, resource_path)


def main():
    required_if = [
        ("state", "present", ["dsn"])
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name", "state"),
            dsn=dict(),
            pool_size=dict(
                type="int",
            )
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    list_path = utils.build_url_path(API_GROUP, API_VERSION, None, "provider")
    resource_path = utils.build_url_path(
        API_GROUP, API_VERSION, None, "provider", module.params["name"],
    )
    payload = dict(
        type="PostgresConfig",
        api_version=API_VERSION,
        metadata=dict(name=module.params["name"]),
        spec=arguments.get_spec_payload(module.params, "dsn", "pool_size"),
    )

    try:
        changed, datastore = sync(
            module.params["state"], client, list_path, resource_path, payload,
            module.check_mode,
        )
        module.exit_json(changed=changed, object=datastore)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
