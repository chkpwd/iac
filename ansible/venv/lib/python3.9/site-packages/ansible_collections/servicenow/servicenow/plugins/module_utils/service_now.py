# -*- coding: utf-8 -*-
# Copyright: (c) 2019-2021, Ansible Project
# Copyright: (c) 2017, Tim Rightnour <thegarbledone@gmail.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function
__metaclass__ = type
import traceback
import logging
import time

from ansible.module_utils.basic import AnsibleModule, env_fallback, missing_required_lib

# Pull in pysnow
HAS_PYSNOW = False
PYSNOW_IMP_ERR = None
try:
    import pysnow
    HAS_PYSNOW = True
except ImportError:
    PYSNOW_IMP_ERR = traceback.format_exc()

# Pull in requests
HAS_REQUESTS = False
REQUESTS_IMP_ERR = None
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    REQUESTS_IMP_ERR = traceback.format_exc()


if HAS_REQUESTS:
    class HTTPBearerAuth(requests.auth.AuthBase):
        """A :class:`requests.auth.AuthBase` bearer token authentication method
        per https://2.python-requests.org/en/master/user/authentication/#new-forms-of-authentication

        :param token: Bearer token to be used instead of user/pass or session
        """

        def __init__(self, token):
            self.token = token

        def __call__(self, r):
            r.headers['Authorization'] = "Bearer {0}".format(str(self.token))
            return r
else:
    class HTTPBearerAuth(object):
        pass


class ServiceNowModule(AnsibleModule):

    def __init__(self, required_together=None, mutually_exclusive=None, required_one_of=None, *args, **kwargs):
        ''' Constructor - This module mediates interactions with Service Now.

        :module: ServiceNowModule extended from AnsibleModule.
        '''

        # Initialize instance arguments
        self._required_together = [
            ['username', 'password'],
            ['client_id', 'client_secret'],
        ]
        if required_together is None:
            self.required_together = self._required_together
        else:
            self.required_together.append(self._required_together)

        self._mutually_exclusive = [
            ['host', 'instance'],
            ['openid_issuer', 'openid'],
            ['openid_scope', 'openid']
        ]
        if mutually_exclusive is None:
            self.mutually_exclusive = self._mutually_exclusive
        else:
            self.mutually_exclusive.append(self._mutually_exclusive)

        self._required_one_of = [
            ['host', 'instance'],
        ]
        if required_one_of is None:
            self.required_one_of = self._required_one_of
        else:
            self.required_one_of.append(self._required_one_of)

        # Initialize AnsibleModule superclass before params
        super(ServiceNowModule, self).__init__(
            required_together=self.required_together,
            mutually_exclusive=self.mutually_exclusive,
            required_one_of=self.required_one_of,
            *args,
            **kwargs
        )

        # Output of module
        self.result = {}

        # OpenID information
        self.openid = {}
        self.openid['url'] = {}

        # Authenticated connection
        self.connection = None

        if not HAS_PYSNOW:
            AnsibleModule.fail_json(self, msg=missing_required_lib('pysnow'),
                                    exception=PYSNOW_IMP_ERR)
        if not HAS_REQUESTS:
            AnsibleModule.fail_json(self, msg=missing_required_lib('requests'),
                                    exception=REQUESTS_IMP_ERR)

        # Params
        #

        # REQUIRED: Their absence will chuck a rod
        # Turn on debug if not specified, but ANSIBLE_DEBUG is set
        self.module_debug = {}
        if self._debug:
            self.warn('Enable debug output because ANSIBLE_DEBUG was set.')
            self.params['log_level'] = 'debug'
        self.log_level = (self.params['log_level']).lower
        if self.log_level == 'debug':
            # Turn on debugging
            logging.basicConfig(level=logging.DEBUG)
            logging.debug("Debug on for ServiceNowModule.")

        self.auth = (self.params['auth']).lower
        self.raise_on_empty = self.params['raise_on_empty']
        if self.raise_on_empty:
            self.raise_on_empty = None

        # OPTIONAL: Use params.get() to gracefully fail
        self.instance = self.params.get('instance')
        self.host = self.params.get('host')
        self.username = self.params.get('username')
        self.password = self.params.get('password')
        self.client_id = self.params.get('client_id')
        self.client_secret = self.params.get('client_secret')
        self.token = self.params.get('token')

        # OpenID
        if self.params.get('openid') is not None:
            self.openid = self.params.get('openid')
            self.token = self.openid['id_token']
            if not isinstance(self.openid['scope'], list):
                self.openid['scope'] = list(self.openid['scope'].split(' '))
        else:
            self.openid['iss'] = self.params.get('openid_issuer')
            self.openid['scope'] = self.params.get('openid_scope')
            self.openid['url']['introspect'] = "{0}/v1/introspect".format(
                self.openid['iss'])
            self.openid['url']['token'] = "{0}/v1/token".format(
                self.openid['iss'])
            self.openid['url']['userinfo'] = "{0}/v1/userinfo".format(
                self.openid['iss'])

        # Log into Service Now
        self._login()

    # Debugging
    #
    # Tools to handle debugging output from the APIs.
    def _mod_debug(self, key, **kwargs):
        self.module_debug[key] = kwargs
        if 'module_debug' not in self.module_debug:
            self.module_debug = dict(key=kwargs)
        else:
            self.module_debug.update(key=kwargs)

    # Login
    #
    # Connect using the method specified by 'auth'
    def _login(self):
        self.result['changed'] = False
        if self.params['auth'] == 'basic':
            if self.client_id is not None:
                self._auth_oauth()
            else:
                self._auth_basic()
        elif self.params['auth'] == 'oauth':
            self._auth_oauth()
        elif self.params['auth'] == 'token':
            self._auth_token()
        elif self.params['auth'] == 'openid':
            self._auth_openid()
        else:
            self.fail(
                msg="Auth method not implemented: {0}".format(
                    self.params['auth']
                )
            )

    # Basic
    #
    # Connect using username and password
    def _auth_basic(self):
        try:
            self.connection = pysnow.Client(
                instance=self.instance,
                host=self.host,
                user=self.username,
                password=self.password,
                raise_on_empty=self.raise_on_empty
            )
        except Exception as detail:
            self.fail(
                msg='Could not connect to ServiceNow: {0}'.format(
                    str(detail)
                )
            )

    # OAuth
    #
    # Connect using client id and secret in addition to Basic
    def _auth_oauth(self):
        try:
            self.connection = pysnow.OAuthClient(
                client_id=self.client_id,
                client_secret=self.client_secret,
                token_updater=self._oauth_token_updater,
                instance=self.instance,
                host=self.host,
                raise_on_empty=self.raise_on_empty
            )
        except Exception as detail:
            self.fail(
                msg='Could not connect to ServiceNow: {0}'.format(
                    str(detail)
                )
            )
        if not self.token:
            # No previous token exists, Generate new.
            try:
                self.token = self.connection.generate_token(
                    self.username,
                    self.password
                )
            except pysnow.exceptions.TokenCreateError as detail:
                self.fail(
                    msg='Unable to generate a new token: {0}'.format(
                        str(detail)
                    )
                )
            self.connection.set_token(self.token)

    def _oauth_token_updater(self, new_token):
        self.token = new_token
        self.connection = pysnow.OAuthClient(
            client_id=self.client_id,
            client_secret=self.client_secret,
            token_updater=self._oauth_token_updater,
            instance=self.instance,
            host=self.host,
            raise_on_empty=self.raise_on_empty
        )
        try:
            self.connection.set_token(self.token)
        except pysnow.exceptions.MissingToken:
            self.module.fail(msg="Token is missing")
        except Exception as detail:
            self.module.fail(
                msg='Could not refresh token: {0}'.format(
                    str(detail)
                )
            )

    # Token
    #
    # Use a supplied token instead of client id and secret.
    def _auth_token(self):
        try:
            s = requests.Session()
            s.auth = HTTPBearerAuth(self.token)
            self.connection = pysnow.Client(
                instance=self.instance,
                host=self.host,
                session=s,
                raise_on_empty=self.raise_on_empty
            )
        except Exception as detail:
            self.fail(
                msg='Could not connect to ServiceNow: {0}'.format(
                    str(detail)
                )
            )

    # OpenID
    #
    # Use the OpenID Connect protocol to obtain a bearer token.
    def _auth_openid(self):
        if self.openid['iss'] is None:
            self.fail(msg='OpenID requires openid_issuer be specified.')

        if self.token is None:
            self._openid_get_token()
        else:
            if 'active' not in self.openid.keys():
                self._openid_inspect_token()
            if 'drift' in self.openid and self.openid['drift'] > 0:
                expires = self.openid['exp'] - self.openid['drift']
            else:
                expires = self.openid['exp']
            now = int(time.time())
            if not self.openid['active'] or now >= expires:
                self._openid_get_token()
            else:
                self._openid_result()
        self._auth_token()

    def _openid_get_token(self):
        self.openid['iatlocal'] = int(time.time())
        r = requests.post(
            self.openid['url']['token'],
            auth=(self.client_id, self.client_secret),
            headers={
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded'
            },
            data={
                'grant_type': 'password',
                'username': self.username,
                'password': self.password,
                'scope': ''.join(str(e) for e in self.openid['scope'])
            }
        )
        self._openid_response(r)
        self.token = self.openid['id_token']
        self._openid_inspect_token()

    def _openid_inspect_token(self):
        r = requests.post(
            self.openid['url']['introspect'],
            auth=(self.client_id, self.client_secret),
            headers={
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded'
            },
            params={
                'token': self.token,
                'token_type_hint': 'id_token'
            }
        )
        self._openid_response(r)

    def _openid_response(self, r):
        r.raise_for_status()
        self.openid.update(r.json())
        if 'drift' not in self.openid and 'iat' in self.openid:
            self.openid['drift'] = self.openid['iat'] - self.openid['iatlocal']
        self._openid_result()

    def _openid_result(self):
        if 'openid' not in self.result.keys():
            self.result['openid'] = self.openid
        else:
            self.result['openid'].update(self.openid)

    #
    # Extend AnsibleModule methods
    #

    def fail(self, msg):
        if self.log_level == 'debug':
            pass
        AnsibleModule.fail_json(self, msg=msg, **self.result)

    def exit(self):
        '''Called to end module'''
        if 'invocation' not in self.result:
            self.result['invocation'] = {
                'module_args': self.params,
                #               'module_kwargs': {
                #                  'ServiceNowModuleKWArgs': self.ServiceNowModuleKWArgs,
                #               }
            }
        if self.log_level == 'debug':
            if self.module_debug:
                self.result['invocation'].update(
                    module_debug=self.module_debug)
        AnsibleModule.exit_json(self, **self.result)

    def _merge_dictionaries(self, a, b):
        new = a.copy()
        new.update(b)
        return new

    @staticmethod
    def create_argument_spec():
        argument_spec = dict(
            auth=dict(
                type='str',
                choices=[
                    'basic',
                    'oauth',
                    'token',
                    'openid',
                ],
                default='basic',
                fallback=(
                    env_fallback,
                    ['SN_AUTH']
                )
            ),
            log_level=dict(
                type='str',
                choices=[
                    'debug',
                    'info',
                    'normal',
                ],
                default='normal'
            ),
            raise_on_empty=dict(
                type='bool',
                default=True
            ),
            instance=dict(
                type='str',
                required=False,
                fallback=(
                    env_fallback,
                    ['SN_INSTANCE']
                )
            ),
            host=dict(
                type='str',
                required=False,
                fallback=(
                    env_fallback,
                    ['SN_HOST']
                )
            ),
            username=dict(
                type='str',
                required=False,
                fallback=(
                    env_fallback,
                    ['SN_USERNAME']
                )
            ),
            password=dict(
                type='str',
                required=False,
                no_log=True,
                fallback=(
                    env_fallback,
                    ['SN_PASSWORD']
                )
            ),
            client_id=dict(
                type='str',
                required=False,
                no_log=True,
                fallback=(
                    env_fallback,
                    ['SN_CLIENTID']
                )
            ),
            client_secret=dict(
                type='str',
                required=False,
                no_log=True,
                fallback=(
                    env_fallback,
                    ['SN_CLIENTSECRET']
                )
            ),
            token=dict(
                type='str',
                required=False,
                no_log=True,
                fallback=(
                    env_fallback,
                    ['SN_TOKEN']
                )
            ),
            openid=dict(
                type='dict',
                required=False
            ),
            openid_issuer=dict(
                type='str',
                required=False,
                fallback=(
                    env_fallback,
                    ['OPENID_ISSUER']
                )
            ),
            # offline_access is not supported.
            openid_scope=dict(
                type='list',
                elements='str',
                required=False,
                default=['openid'],
                fallback=(
                    env_fallback,
                    ['OPENID_SCOPE']
                )
            ),
        )
        return argument_spec
