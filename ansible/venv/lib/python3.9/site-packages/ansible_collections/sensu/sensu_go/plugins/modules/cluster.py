#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, XLAB Steampunk <steampunk@xlab.si>
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
module: cluster
author:
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu Go clusters
description:
  - Create, update or delete Sensu cluster.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/deploy-sensu/cluster-sensu/).
version_added: 1.9.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.cluster_info
options:
  api_urls:
    description:
      - List of API urls that compose a single cluster.
      - Required if I(state) is C(present).
    type: list
    elements: str
"""

EXAMPLES = """
- name: Create a small cluster
  sensu.sensu_go.cluster:
    name: small-cluster
    api_urls: https://sensu.alpha.example.com:8080

- name: Create a larger cluster
  sensu.sensu_go.cluster:
    name: large-cluster
    api_urls:
      - https://sensu.alpha.example.com:8080
      - https://sensu.beta.example.com:8080
      - https://sensu.gamma.example.com:8080

- name: Delete a cluster
  sensu.sensu_go.cluster:
    name: small-cluster
    state: absent
"""

RETURN = """
object:
  description: Object representing Sensu cluster.
  returned: success
  type: dict
  sample:
    metadata:
      name: alpha-cluster
    api_urls:
      - "http://10.10.0.1:8080"
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "federation/v1"


def main():
    required_if = [
        ("state", "present", ["api_urls"]),
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name", "state"),
            api_urls=dict(type="list", elements="str"),
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, None, "clusters", module.params["name"],
    )

    payload = dict(
        type="Cluster",
        api_version=API_VERSION,
        metadata=dict(name=module.params["name"]),
        spec=arguments.get_spec_payload(module.params, "api_urls"),
    )
    try:
        changed, cluster = utils.sync_v1(
            module.params["state"], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=cluster)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
