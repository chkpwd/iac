#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: infini_user
version_added: '2.9.0'
short_description: Create, Delete and Modify a User on Infinibox
description:
    - This module creates, deletes or modifies a user on Infinibox.
author: David Ohlemacher (@ohlemacher)
options:
  user_name:
    description:
      - The new user's Name. Once a user is created, the user_name may not be
        changed from this module. It may be changed from the UI or from
        infinishell.
    required: true
    type: str
  user_email:
    description:
      - The new user's Email address
    required: false
    type: str
  user_password:
    description:
      - The new user's password
    required: false
    type: str
  user_role:
    description:
      - The user's role
    required: false
    choices: [ "admin", "pool_admin", "read_only" ]
    type: str
  user_enabled:
    description:
      - Specify whether to enable the user
    type: bool
    required: false
    default: true
  user_pool:
    description:
      - Use with role==pool_admin. Specify the new user's pool.
    required: false
    type: str
  state:
    description:
      - Creates/Modifies user when present or removes when absent
    required: false
    default: present
    choices: [ "stat", "reset_password", "present", "absent" ]
    type: str

extends_documentation_fragment:
    - infinibox
'''

EXAMPLES = r'''
- name: Create new user
  infini_user:
    user_name: foo_user
    user_email: foo@example.com
    user_password: secret2
    user_role: pool_admin
    user_enabled: false
    pool: foo_pool
    state: present
    password: secret1
    system: ibox001
'''

# RETURN = r''' # '''


from ansible.module_utils.basic import AnsibleModule, missing_required_lib

import traceback

from ansible_collections.infinidat.infinibox.plugins.module_utils.infinibox import (
    HAS_INFINISDK,
    api_wrapper,
    infinibox_argument_spec,
    get_system,
    get_user,
    get_pool,
    unixMillisecondsToDate,
    merge_two_dicts,
)

try:
    from infi.dtypes.iqn import make_iscsi_name
except ImportError:
    pass  # Handled by HAS_INFINISDK from module_utils


@api_wrapper
def create_user(module, system):
    if not module.check_mode:
        user = system.users.create(name=module.params['user_name'],
                                   password=module.params['user_password'],
                                   email=module.params['user_email'],
                                   enabled=module.params['user_enabled'],
                                   )
        # Set the user's role
        user.update_role(module.params['user_role'])
        if module.params['user_pool']:
            if not module.params['user_role'] == 'pool_admin':
                raise AssertionError("user_pool set, but role is not 'pool_admin'")
            # Add the user to the pool's owners
            pool = system.pools.get(name=module.params['user_pool'])
            add_user_to_pool_owners(user, pool)
    changed = True
    return changed


def add_user_to_pool_owners(user, pool):
    """
    Find the current list of pool owners and add user using pool.set_owners().
    set_owners() replaces the current owners with the list of new owners. So,
    get owners, add user, then set owners.  Further, we need to know if the
    owners changed.  Use sets of owners to compare.
    """
    # print("add_user_to_pool_owners(): start")
    changed = False
    pool_fields = pool.get_fields(from_cache=True, raw_value=True)
    pool_owners = pool_fields.get('owners', [])
    # print('pool_owners:', pool_owners, 'pool_owners type:', type(pool_owners))
    # print('user:', user)
    # print('pool:', pool)
    pool_owners_set = set(pool_owners)
    # print('pool_owners_set:', pool_owners_set)
    new_pool_owners_set = pool_owners_set.copy()
    new_pool_owners_set.add(user.id)
    # print('new_pool_owners_set:', new_pool_owners_set)
    if pool_owners_set != new_pool_owners_set:
        pool.set_owners([user])
        changed = True
    # print("changed:", changed)
    # print("add_user_to_pool_owners(): end")
    return changed


def remove_user_from_pool_owners(user, pool):
    changed = False
    pool_fields = pool.get_fields(from_cache=True, raw_value=True)
    pool_owners = pool_fields.get('owners', [])
    try:
        pool_owners.remove(user)
        pool.set_owners(pool_owners)
        changed = True
    except ValueError:
        pass  # User is not a pool owner
    return changed


@api_wrapper
def update_user(module, system, user):
    # print("update_user()")
    if user is None:
        raise AssertionError("Cannot update user {0}. User not found.".format(module.params["user_name"]))

    changed = False
    fields = user.get_fields(from_cache=True, raw_value=True)
    if fields.get('role') != module.params['user_role'].upper():
        user.update_field('role', module.params['user_role'])
        changed = True
    if fields.get('enabled') != module.params['user_enabled']:
        user.update_field('enabled', module.params['user_enabled'])
        changed = True
    if fields.get('email') != module.params['user_email']:
        user.update_field('email', module.params['user_email'])
        changed = True

    if module.params['user_pool']:
        try:
            pool_name = module.params['user_pool']
            pool = system.pools.get(name=pool_name)
        except Exception as err:
            module.fail_json(msg='Cannot find pool {0}: {1}'.format(pool_name, err))
        if add_user_to_pool_owners(user, pool):
            changed = True
    return changed


@api_wrapper
def reset_user_password(module, system, user):
    # print("update_user()")
    if user is None:
        raise AssertionError("Cannot change user {0} password. User not found.".format(module.params["user_name"]))
    user.update_password(module.params['user_password'])


@api_wrapper
def delete_user(module, user):
    if not user:
        return False

    changed = True
    if not module.check_mode:
        # May raise APICommandFailed if mapped, etc.
        user.delete()
    return changed


def get_sys_user(module):
    system = get_system(module)
    user = get_user(module, system)
    # print("get_sys_user(): user:", user)
    return (system, user)


def get_user_fields(user):
    pools = user.get_owned_pools()
    pool_names = [pool.get_field('name') for pool in pools]

    fields = user.get_fields(from_cache=True, raw_value=True)
    field_dict = dict(
        id=user.id,
        enabled=fields.get('enabled', None),
        role=fields.get('role', None),
        email=fields.get('email', None),
        pools=pool_names,
    )
    return field_dict


def handle_stat(module):
    system, user = get_sys_user(module)
    user_name = module.params["user_name"]
    if not user:
        module.fail_json(msg='User {0} not found'.format(user_name))
    field_dict = get_user_fields(user)
    result = dict(
        changed=False,
        msg='User stat found'
    )
    result = merge_two_dicts(result, field_dict)
    module.exit_json(**result)


def handle_present(module):
    system, user = get_sys_user(module)
    user_name = module.params["user_name"]
    if not user:
        changed = create_user(module, system)
        msg = 'User {0} created'.format(user_name)
    else:
        changed = update_user(module, system, user)
        if changed:
            msg = 'User {0} updated'.format(user_name)
        else:
            msg = 'User {0} update required no changes'.format(user_name)
    module.exit_json(changed=changed, msg=msg)


def handle_absent(module):
    system, user = get_sys_user(module)
    user_name = module.params["user_name"]
    if not user:
        changed = False
        msg = "User {0} already absent".format(user_name)
    else:
        changed = delete_user(module, user)
        msg = "User {0} removed".format(user_name)
    module.exit_json(changed=changed, msg=msg)


def handle_reset_password(module):
    system, user = get_sys_user(module)
    user_name = module.params["user_name"]
    if not user:
        msg = 'Cannot change password. User {0} not found'.format(user_name)
        module.fail_json(msg=msg)
    else:
        reset_user_password(module, system, user)
        msg = 'User {0} password changed'.format(user_name)
        module.exit_json(changed=True, msg=msg)


def execute_state(module):
    state = module.params['state']
    try:
        if state == 'stat':
            handle_stat(module)
        elif state == 'present':
            handle_present(module)
        elif state == 'absent':
            handle_absent(module)
        elif state == 'reset_password':
            handle_reset_password(module)
        else:
            module.fail_json(msg='Internal handler error. Invalid state: {0}'.format(state))
    finally:
        system = get_system(module)
        system.logout()


def check_options(module):
    state = module.params['state']
    user_role = module.params['user_role']
    user_pool = module.params['user_pool']
    if state == 'present':
        if user_role == 'pool_admin' and not user_pool:
            module.fail_json(msg='user_role "pool_admin" requires a user_pool to be provided')
        if user_role != 'pool_admin' and user_pool:
            module.fail_json(msg='Only user_role "pool_admin" should have a user_pool provided')

        valid_keys = ['user_email', 'user_password', 'user_role', 'user_enabled']
        for valid_key in valid_keys:
            # Check required keys provided
            try:
                not_used = module.params[valid_key]
            except KeyError:
                msg = 'For state "present", options {0} are required'.format(", ".join(valid_keys))
                module.fail_json(msg=msg)
    elif state == 'reset_password':
        if not module.params['user_password']:
            msg = 'For state "reset_password", user_password is required'


def main():
    argument_spec = infinibox_argument_spec()
    argument_spec.update(
        dict(
            user_name=dict(required=True),
            user_email=dict(required=False),
            user_password=dict(required=False, no_log=True),
            user_role=dict(required=False, choices=['admin', 'pool_admin', 'read_only']),
            user_enabled=dict(required=False, type='bool', default=True),
            user_pool=dict(required=False),
            state=dict(default='present', choices=['stat', 'reset_password', 'present', 'absent']),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    if not HAS_INFINISDK:
        module.fail_json(msg=missing_required_lib('infinisdk'))

    check_options(module)
    execute_state(module)


if __name__ == '__main__':
    main()
