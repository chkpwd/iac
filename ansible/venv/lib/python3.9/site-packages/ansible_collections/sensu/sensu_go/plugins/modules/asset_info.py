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

DOCUMENTATION = """
module: asset_info
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu assets
description:
  - Retrieve information about Sensu Go assets.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/assets/).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.info
  - sensu.sensu_go.namespace
seealso:
  - module: sensu.sensu_go.asset
  - module: sensu.sensu_go.bonsai_asset
"""

EXAMPLES = """
- name: List all Sensu assets
  sensu.sensu_go.asset_info:
  register: result

- name: List the selected Sensu asset
  sensu.sensu_go.asset_info:
    name: my_asset
  register: result

- name: Do something with result
  ansible.builtin.debug:
    msg: "{{ result.objects.0.metadata.name }}"

"""

RETURN = """
objects:
  description: List of Sensu assets.
  returned: success
  type: list
  elements: dict
  sample:
    - metadata:
        name: check_script
        namespace: default
      builds:
        - sha512: 4f926bf4328f...2c58ad9ab40c9e2edc31b288d066b195b21b
          url: http://example.com/asset.tar.gz
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "namespace"),
            name=dict(),  # Name is not required in info modules.
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_core_v2_path(
        module.params["namespace"], "assets", module.params["name"],
    )

    try:
        assets = utils.prepare_result_list(utils.get(client, path))
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=assets)


if __name__ == "__main__":
    main()
