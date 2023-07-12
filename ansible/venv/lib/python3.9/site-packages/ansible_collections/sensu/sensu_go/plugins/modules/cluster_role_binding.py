#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Paul Arthur <paul.arthur@flowerysong.com>
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
module: cluster_role_binding
author:
 - Paul Arthur (@flowerysong)
 - Manca Bizjak (@mancabizjak)
 - Aljaz Kosir (@aljazkosir)
 - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu cluster role bindings
description:
  - Create, update or delete Sensu cluster role binding.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#role-bindings-and-cluster-role-bindings).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
options:
  cluster_role:
    description:
      - Name of the cluster role.
      - Required if I(state) is C(present).
    type: str
  users:
    description:
      - List of users to bind to the cluster role.
      - Note that at least one of I(users) and I(groups) must be
        specified when creating a cluster role binding.
    type: list
    elements: str
  groups:
    description:
      - List of groups to bind to the cluster role.
      - Note that at least one of I(users) and I(groups) must be
        specified when creating a cluster role binding.
    type: list
    elements: str
seealso:
  - module: sensu.sensu_go.cluster_role_binding_info
  - module: sensu.sensu_go.cluster_role
  - module: sensu.sensu_go.role_binding
'''

EXAMPLES = '''
- name: Create a cluster role binding
  sensu.sensu_go.cluster_role_binding:
    name: all-cluster-admins
    cluster_role: cluster-admin
    groups:
      - cluster-admins
    users:
      - alice

- name: Delete a cluster role binding
  sensu.sensu_go.cluster_role_binding:
    name: all-cluster-admins
    state: absent
'''

RETURN = '''
object:
  description: Object representing Sensu cluster role binding.
  returned: success
  type: dict
  sample:
    metadata:
      name: cluster-admin
    role_ref:
      name: cluster-admin
      type: ClusterRole
    subjects:
      - name: cluster-admins
        type: Group
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils, role_utils


def build_api_payload(params):
    payload = arguments.get_mutation_payload(params)
    payload["subjects"] = role_utils.build_subjects(params["groups"], params["users"])
    payload["role_ref"] = role_utils.type_name_dict("ClusterRole", params["cluster_role"])

    return payload


def main():
    required_if = [
        ("state", "present", ["cluster_role"])
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name", "state"),
            cluster_role=dict(),
            users=dict(
                type="list", elements="str",
            ),
            groups=dict(
                type="list", elements="str",
            ),
        )
    )

    msg = role_utils.validate_binding_module_params(module.params)
    if msg:
        module.fail_json(msg=msg)

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        None, "clusterrolebindings", module.params["name"],
    )
    payload = build_api_payload(module.params)

    try:
        changed, cluster_role_binding = utils.sync(
            module.params["state"], client, path, payload, module.check_mode, role_utils.do_role_bindings_differ
        )
        module.exit_json(changed=changed, object=cluster_role_binding)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
