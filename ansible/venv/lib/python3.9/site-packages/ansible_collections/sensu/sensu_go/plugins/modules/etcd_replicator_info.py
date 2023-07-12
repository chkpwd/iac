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
module: etcd_replicator_info
author:
  - Tadej Borovsak (@tadeboro)
short_description: List available Sensu Go etcd replicators
description:
  - Retrieve information about Sensu Go etcd replicators.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/deploy-sensu/etcdreplicators/).
version_added: 1.9.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
seealso:
  - module: sensu.sensu_go.etcd_replicator
"""

EXAMPLES = """
- name: List all Sensu Go etcd replicators
  sensu.sensu_go.etcd_replicator_info:
  register: result

- name: Retrieve the selected Sensu Go etcd replicator
  sensu.sensu_go.etcd_replicator_info:
    name: role_replicator
  register: result

- name: Do something with result
  ansible.builtin.debug:
    msg: "{{ result.objects.0.resource }}"
"""

RETURN = """
objects:
  description: List of Sensu Go etcd replicators.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        created_by: admin
        name: cluster-role-replicator
      api_version: core/v2
      ca_cert: /etc/sensu/certs/ca.pem
      cert: /etc/sensu/certs/cert.pem
      insecure: false
      key: /etc/sensu/certs/key.pem
      namespace: ""
      replication_interval_seconds: 30
      resource: ClusterRole
      url: https://sensu.alpha.example.com:2379
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "federation/v1"


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
        API_GROUP, API_VERSION, None, "etcd-replicators", module.params["name"],
    )

    try:
        replicators = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    # We simulate the behavior of v2 API here and only return the spec.
    module.exit_json(changed=False, objects=[
        utils.convert_v1_to_v2_response(s) for s in replicators
    ])


if __name__ == "__main__":
    main()
