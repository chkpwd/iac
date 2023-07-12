#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_fs
version_added: '2.3.0'
short_description: Create, Delete or Modify filesystems on Infinibox
description:
    - This module creates, deletes or modifies filesystems on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  name:
    description:
      - File system name.
    required: true
    type: str
  state:
    description:
      - Creates/Modifies file system when present or removes when absent.
    required: false
    default: present
    choices: [ "stat", "present", "absent" ]
    type: str
  thin_provision:
    description:
      - Whether the master file system should be thin or thick provisioned.
    required: false
    default: true
    type: bool
  pool:
    description:
      - Pool that will host file system.
    required: true
    type: str
  size:
    description:
      - File system size in MB, GB or TB units. See examples.
    required: false
    type: str
extends_documentation_fragment:
    - infinibox
requirements:
    - capacity
'''

EXAMPLES = r'''
- name: Create new file system named foo under pool named bar
  infini_fs:
    name: foo
    size: 1TB
    pool: bar
    thin_provision: true
    state: present
    user: admin
    password: secret
    system: ibox001
'''

# RETURN = r''' # '''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

import traceback

try:
    from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
        HAS_INFINISDK,
        api_wrapper,
        infinibox_argument_spec,
        get_pool,
        get_system,
        get_filesystem
    )
except ModuleNotFoundError:
    from infinibox import (  # Used when hacking
        HAS_INFINISDK,
        api_wrapper,
        infinibox_argument_spec,
        get_pool,
        get_system,
        get_filesystem
    )

CAPACITY_IMP_ERR = None
try:
    from capacity import KiB, Capacity
    HAS_CAPACITY = True
except ImportError:
    HAS_CAPACITY = False


@api_wrapper
def create_filesystem(module, system):
    """Create Filesystem"""
    changed = True
    if not module.check_mode:
        if module.params['thin_provision']:
            provisioning = 'THIN'
        else:
            provisioning = 'THICK'
        filesystem = system.filesystems.create(
            name=module.params['name'],
            pool=get_pool(module, system),
            provtype=provisioning,
        )

        if module.params['size']:
            size = Capacity(module.params['size']).roundup(64 * KiB)
            filesystem.update_size(size)
    return changed


@api_wrapper
def update_filesystem(module, filesystem):
    """Update Filesystem"""
    changed = False
    if module.params['size']:
        size = Capacity(module.params['size']).roundup(64 * KiB)
        if filesystem.get_size() != size:
            if not module.check_mode:
                filesystem.update_size(size)
            changed = True

        provisioning = str(filesystem.get_provisioning())
        if provisioning == 'THICK' and module.params['thin_provision']:
            if not module.check_mode:
                filesystem.update_provisioning('THIN')
            changed = True
        if provisioning == 'THIN' and not module.params['thin_provision']:
            if not module.check_mode:
                filesystem.update_provisioning('THICK')
            changed = True
    return changed


@api_wrapper
def delete_filesystem(module, filesystem):
    """ Delete Filesystem"""
    if not module.check_mode:
        filesystem.delete()
    module.exit_json(changed=True)


def get_sys_pool_fs(module):
    system = get_system(module)
    pool = get_pool(module, system)
    filesystem = get_filesystem(module, system)
    return (system, pool, filesystem)


def handle_stat(module):
    system, pool, filesystem = get_sys_pool_fs(module)
    if not pool:
        module.fail_json(msg='Pool {0} not found'.format(module.params['pool']))
    if not filesystem:
        module.fail_json(msg='File system {0} not found'.format(module.params['name']))
    fields = filesystem.get_fields()  # from_cache=True, raw_value=True)
    name = fields.get("name", None)
    used = fields.get('used_size', None)
    filesystem_id = fields.get('id', None)
    provisioning = fields.get('provisioning', None)

    result = dict(
        changed=False,
        name=name,
        size=str(filesystem.get_size()),
        used=str(used),
        filesystem_id=filesystem_id,
        provisioning=provisioning,
        msg='File system stat found'
    )
    module.exit_json(**result)


def handle_present(module):
    system, pool, filesystem = get_sys_pool_fs(module)
    if not pool:
        module.fail_json(msg='Pool {0} not found'.format(module.params['pool']))
    if not filesystem:
        changed = create_filesystem(module, system)
        module.exit_json(changed=changed, msg="File system created")
    else:
        changed = update_filesystem(module, filesystem)
        module.exit_json(changed=changed, msg="File system updated")


def handle_absent(module):
    system, pool, filesystem = get_sys_pool_fs(module)
    if not pool or not filesystem:
        module.exit_json(changed=False, msg="File system already absent")
    else:
        changed = delete_filesystem(module, filesystem)
        module.exit_json(changed=changed, msg="File system removed")


def execute_state(module):
    state = module.params['state']
    try:
        if state == 'stat':
            handle_stat(module)
        elif state == 'present':
            handle_present(module)
        elif state == 'absent':
            handle_absent(module)
        else:
            module.fail_json(msg='Internal handler error. Invalid state: {0}'.format(state))
    finally:
        system = get_system(module)
        system.logout()


def main():
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            name=dict(required=True),
            state=dict(default='present', choices=['stat', 'present', 'absent']),
            pool=dict(required=True),
            size=dict(),
            thin_provision=dict(type=bool, default=True),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    if not HAS_CAPACITY:
        module.fail_json(msg=missing_required_lib('capacity'))

    if module.params['size']:
        try:
            Capacity(module.params['size'])
        except Exception:
            module.fail_json(msg='size (Physical Capacity) should be defined in MB, GB, TB or PB units')

    execute_state(module)


if __name__ == '__main__':
    main()
