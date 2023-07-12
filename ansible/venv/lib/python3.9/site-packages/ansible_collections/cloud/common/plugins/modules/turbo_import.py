#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (C) 2022, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: turbo_import
short_description: A demo module to test import logic for turbo mode
version_added: "1.0.0"
description:
- "This module tests the import logic for turbo mode."
author:
- Mike Graves (@gravesm)
"""

EXAMPLES = r"""
- name: Run the module
  cloud.common.turbo_import:
"""


from ansible_collections.cloud.common.plugins.module_utils.turbo.module import (
    AnsibleTurboModule as AnsibleModule,
)


def run_module():
    module = AnsibleModule(argument_spec={})
    module.collection_name = "cloud.common"
    module.exit_json(changed=False)


def main():
    from ansible_collections.cloud.common.plugins.module_utils import turbo_demo

    run_module()


if __name__ == "__main__":
    main()
