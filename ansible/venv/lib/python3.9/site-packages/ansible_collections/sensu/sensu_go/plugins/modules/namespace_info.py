#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Paul Arthur <paul.arthur@flowerysong.com>
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
module: namespace_info
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Miha Plesko (@miha-plesko)
  - Tadej Borovsak (@tadeboro)
short_description: List Sensu namespaces
description:
  - Retrieve information about Sensu namespaces.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#namespaces).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
notes:
  - Currently, it is not possible to retrieve information about a single
    namespace because namespace is not much more than a name itself.
seealso:
  - module: sensu.sensu_go.namespace
'''

EXAMPLES = '''
- name: List Sensu namespaces
  sensu.sensu_go.namespace_info:
  register: result
'''

RETURN = '''
objects:
  description: List of Sensu namespaces.
  returned: success
  type: list
  elements: dict
  sample:
    - name: default
'''

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth"),
        ),
    )
    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(None, 'namespaces')

    try:
        namespaces = utils.get(client, path)
    except errors.Error as e:
        module.fail_json(msg=str(e))

    module.exit_json(changed=False, objects=namespaces)


if __name__ == '__main__':
    main()
