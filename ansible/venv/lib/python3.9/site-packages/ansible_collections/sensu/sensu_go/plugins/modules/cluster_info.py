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
module: cluster_info
author:
  - Tadej Borovsak (@tadeboro)
short_description: List available Sensu Go clusters
description:
  - Retrieve information about Sensu Go clusters.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/deploy-sensu/cluster-sensu/).
version_added: 1.9.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
seealso:
  - module: sensu.sensu_go.cluster
"""

EXAMPLES = """
- name: List all Sensu Go clusters
  sensu.sensu_go.etcd_replicator_info:
  register: result

- name: Retrieve the selected Sensu Go cluster
  sensu.sensu_go.etcd_replicator_info:
    name: my-cluster
  register: result

- name: Do something with result
  ansible.builtin.debug:
    msg: "{{ result.objects.0.api_urls }}"
"""

RETURN = """
objects:
  description: List of Sensu Go etcd clusters.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: alpha-cluster
      api_urls:
        - "http://10.10.0.1:8080"
    - metadata:
        name: beta-cluster
      api_urls:
        - "https://10.20.0.1:8080"
        - "https://10.20.0.2:8080"
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
        API_GROUP, API_VERSION, None, "clusters", module.params["name"],
    )

    try:
        clusters = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    # We simulate the behavior of v2 API here and only return the spec.
    module.exit_json(changed=False, objects=[
        utils.convert_v1_to_v2_response(s) for s in clusters
    ])


if __name__ == "__main__":
    main()
