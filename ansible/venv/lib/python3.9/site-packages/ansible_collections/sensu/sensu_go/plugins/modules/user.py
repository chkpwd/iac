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
module: user
author:
  - Paul Arthur (@flowerysong)
  - Aljaz Kosir (@aljazkosir)
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu users
description:
  - Create, update, activate or deactivate Sensu user.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/reference/rbac/#users).
version_added: 1.0.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
requirements:
  - bcrypt (when managing Sensu Go 5.21.0 or newer)
seealso:
  - module: sensu.sensu_go.user_info
options:
  state:
    description:
      - Desired state of the user.
      - Users cannot actually be deleted, only deactivated.
    type: str
    choices: [ enabled, disabled ]
    default: enabled
  password:
    description:
      - Password for the user.
      - Required if user with a desired name does not exist yet on the backend
        and I(password_hash) is not set.
      - If both I(password) and I(password_hash) are set, I(password_hash) is
        ignored and calculated from the I(password) if required.
    type: str
  password_hash:
    description:
      - Bcrypt password hash for the user.
      - Use C(sensuctl user hash-password PASSWORD) to generate a hash.
      - Required if user with a desired name does not exist yet on the backend
        and I(password) is not set.
      - If both I(password) and I(password_hash) are set, I(password_hash) is
        ignored and calculated from the I(password) if required.
      - Sensu Go < 5.21.0 does not support creating/updating users using
        hashed passwords. Use I(password) parameter if you need to manage such
        Sensu Go installations.
      - At the moment, change detection does not work properly when using
        password hashes because the Sensu Go backend does not expose enough
        information via its API.
    type: str
    version_added: 1.8.0
  groups:
    description:
      - List of groups user belongs to.
    type: list
    elements: str
'''

EXAMPLES = '''
- name: Create a user
  sensu.sensu_go.user:
    auth:
      url: http://localhost:8080
    name: awesome_username
    password: hidden_password?
    groups:
      - dev
      - prod

- name: Use pre-hashed password
  sensu.sensu_go.user:
    auth:
      url: http://localhost:8080
    name: awesome_username
    password_hash: $5f$14$.brXRviMZpbaleSq9kjoUuwm67V/s4IziOLGHjEqxJbzPsreQAyNm

- name: Deactivate a user
  sensu.sensu_go.user:
    name: awesome_username
    state: disabled
'''

RETURN = '''
object:
  description: Object representing Sensu user.
  returned: success
  type: dict
  sample:
    disabled: false
    groups:
      - ops
      - dev
    password: USER_PASSWORD
    password_hash: $5f$14$.brXRviMZpbaleSq9kjoUuwm67V/s4IziOLGHjEqxJbzPsreQAyNm
    username: alice
'''

import traceback

from ansible.module_utils.basic import AnsibleModule, missing_required_lib

from ..module_utils import arguments, errors, utils

try:
    import bcrypt
    HAS_BCRYPT = True
    BCRYPT_IMPORT_ERROR = None
except ImportError:
    HAS_BCRYPT = False
    BCRYPT_IMPORT_ERROR = traceback.format_exc()


def _simulate_backend_response(payload):
    # Backend does not return back any password-related information for now.
    masked_keys = ('password', 'password_hash')
    return dict(
        (k, v) for k, v in payload.items() if k not in masked_keys
    )


def update_password(client, path, username, password, check_mode):
    # Hit the auth testing API and try to validate the credentials. If the API
    # says they are invalid, we need to update them.
    if client.validate_auth_data(username, password):
        return False

    if not check_mode:
        if client.version < "5.21.0":
            utils.put(client, path + '/password', dict(
                username=username, password=password,
            ))
        else:
            hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            utils.put(client, path + '/reset_password', dict(
                username=username, password_hash=hash.decode('ascii'),
            ))

    return True


def update_password_hash(client, path, username, password_hash, check_mode):
    # Some older Sensu Go versions do not have support for password hashes.
    if client.version < "5.21.0":
        raise errors.SensuError(
            "Sensu Go < 5.21.0 does not support password hashes"
        )

    # Insert change detection here once we can receive password hash from the
    # backend. Up until then, we always update passwords.

    if not check_mode:
        utils.put(client, path + '/reset_password', dict(
            username=username, password_hash=password_hash,
        ))

    return True


def update_groups(client, path, old_groups, new_groups, check_mode):
    to_delete = set(old_groups).difference(new_groups)
    to_add = set(new_groups).difference(old_groups)

    if not check_mode:
        # Next few lines are far from atomic, which means that we can leave a
        # user in any of the intermediate states, but this is the best we can
        # do given the API limitations.
        for g in to_add:
            utils.put(client, path + '/groups/' + g, None)
        for g in to_delete:
            utils.delete(client, path + '/groups/' + g)

    return len(to_delete) + len(to_add) > 0


def update_state(client, path, old_disabled, new_disabled, check_mode):
    changed = old_disabled != new_disabled

    if not check_mode and changed:
        if new_disabled:  # `state: disabled` input parameter
            utils.delete(client, path)
        else:  # `state: enabled` input parameter
            utils.put(client, path + '/reinstate', None)

    return changed


def sync(remote_object, client, path, payload, check_mode):
    # Create new user (either enabled or disabled)
    if remote_object is None:
        if check_mode:
            return True, _simulate_backend_response(payload)
        utils.put(client, path, payload)
        return True, utils.get(client, path)

    # Update existing user. We do this on a field-by-field basis because the
    # upsteam API for updating users requires a password field to be set. Of
    # course, we do not want to force users to specify an existing password
    # just for the sake of updating the group membership, so this is why we
    # use field-specific API endpoints to update the user data.

    changed = False

    # We only use password hash if we do not have a password. In practice,
    # this means that users should not set both password and password_hash. We
    # do not enforce this by making those two parameters mutually exclusive
    # because in the future (2.0.0 version of collection), we intend to move
    # password hashing into action plugin and supply both the password and its
    # hash. Why? Because installing bcrypt on control node is way friendlier
    # compared to installing bcrypt on every host that runs our user module.
    #
    # It is true that most of the time, control node == target node in our
    # cases, but not always.
    if 'password' in payload:
        changed = update_password(
            client, path, payload['username'], payload['password'],
            check_mode,
        ) or changed
    elif 'password_hash' in payload:
        changed = update_password_hash(
            client, path, payload['username'], payload['password_hash'],
            check_mode,
        ) or changed

    if 'groups' in payload:
        changed = update_groups(
            client, path, remote_object.get('groups') or [],
            payload['groups'], check_mode,
        ) or changed

    if 'disabled' in payload:
        changed = update_state(
            client, path, remote_object['disabled'], payload['disabled'],
            check_mode,
        ) or changed

    if check_mode:
        # Backend does not return back passwords, so we should follow the
        # example set by the backend API.
        return changed, dict(
            remote_object, **_simulate_backend_response(payload)
        )

    return changed, utils.get(client, path)


def main():
    module = AnsibleModule(
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name"),
            state=dict(
                default='enabled',
                choices=['enabled', 'disabled'],
            ),
            password=dict(
                no_log=True
            ),
            password_hash=dict(
                no_log=False,  # Showing hashes is perfectly OK
            ),
            groups=dict(
                type='list', elements='str',
            )
        ),
    )

    client = arguments.get_sensu_client(module.params['auth'])
    path = utils.build_core_v2_path(None, 'users', module.params['name'])

    try:
        if not HAS_BCRYPT and client.version >= "5.21.0":
            module.fail_json(
                msg=missing_required_lib('bcrypt'),
                exception=BCRYPT_IMPORT_ERROR,
            )
    except errors.SensuError as e:
        module.fail_json(msg=str(e))

    try:
        remote_object = utils.get(client, path)
    except errors.Error as e:
        module.fail_json(msg=str(e))

    if (
        remote_object is None
        and module.params['password'] is None
        and module.params['password_hash'] is None
    ):
        module.fail_json(
            msg='Cannot create new user without a password or a hash'
        )

    payload = arguments.get_spec_payload(
        module.params, 'password', 'password_hash', 'groups',
    )
    payload['username'] = module.params['name']
    payload['disabled'] = module.params['state'] == 'disabled'

    try:
        changed, user = sync(
            remote_object, client, path, payload, module.check_mode
        )
        module.exit_json(changed=changed, object=user)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
