# (c) 2020 CyberArk Software Ltd. All rights reserved.
# (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = """
    name: conjur_variable
    version_added: "1.0.2"
    short_description: Fetch credentials from CyberArk Conjur.
    author:
      - CyberArk BizDev (@cyberark-bizdev)
    description:
      Retrieves credentials from Conjur using the controlling host's Conjur identity
      or environment variables.
      Environment variables could be CONJUR_ACCOUNT, CONJUR_APPLIANCE_URL, CONJUR_CERT_FILE, CONJUR_AUTHN_LOGIN, CONJUR_AUTHN_API_KEY, CONJUR_AUTHN_TOKEN_FILE
      Conjur info - U(https://www.conjur.org/).
    requirements:
      - 'The controlling host running Ansible has a Conjur identity.
        (More: U(https://docs.conjur.org/latest/en/Content/Get%20Started/key_concepts/machine_identity.html))'
    options:
      _terms:
        description: Variable path
        required: True
      validate_certs:
        description: Flag to control SSL certificate validation
        type: boolean
        default: True
      as_file:
        description: >
          Store lookup result in a temporary file and returns the file path. Thus allowing it to be consumed as an ansible file parameter
          (eg ansible_ssh_private_key_file).
        type: boolean
        default: False
      identity_file:
        description: Path to the Conjur identity file. The identity file follows the netrc file format convention.
        type: path
        default: /etc/conjur.identity
        required: False
        ini:
          - section: conjur,
            key: identity_file_path
        env:
          - name: CONJUR_IDENTITY_FILE
      authn_token_file:
        description: Path to the access token file.
        type: path
        default: /var/run/conjur/access-token
        required: False
        ini:
          - section: conjur,
            key: authn_token_file
        env:
          - name: CONJUR_AUTHN_TOKEN_FILE
      config_file:
        description: Path to the Conjur configuration file. The configuration file is a YAML file.
        type: path
        default: /etc/conjur.conf
        required: False
        ini:
          - section: conjur,
            key: config_file_path
        env:
          - name: CONJUR_CONFIG_FILE
"""

EXAMPLES = """
---
  - hosts: localhost
    collections:
      - cyberark.conjur
    tasks:
      - name: Lookup variable in Conjur
        debug:
          msg: "{{ lookup('cyberark.conjur.conjur_variable', '/path/to/secret') }}"
"""

RETURN = """
  _raw:
    description:
      - Value stored in Conjur.
"""

import os.path
import socket
from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from base64 import b64encode
from netrc import netrc
from os import environ
from time import time, sleep
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.urls import urllib_error
from stat import S_IRUSR, S_IWUSR
from tempfile import gettempdir, NamedTemporaryFile
import yaml

from ansible.module_utils.urls import open_url
from ansible.utils.display import Display
import ssl

display = Display()


# Load configuration and return as dictionary if file is present on file system
def _load_conf_from_file(conf_path):
    display.vvv('conf file: {0}'.format(conf_path))

    if not os.path.exists(conf_path):
        return {}
        # raise AnsibleError('Conjur configuration file `{0}` was not found on the controlling host'
        #                    .format(conf_path))

    display.vvvv('Loading configuration from: {0}'.format(conf_path))
    with open(conf_path) as f:
        config = yaml.safe_load(f.read())
        return config


# Load identity and return as dictionary if file is present on file system
def _load_identity_from_file(identity_path, appliance_url):
    display.vvvv('identity file: {0}'.format(identity_path))

    if not os.path.exists(identity_path):
        return {}
        # raise AnsibleError('Conjur identity file `{0}` was not found on the controlling host'
        #                    .format(identity_path))

    display.vvvv('Loading identity from: {0} for {1}'.format(identity_path, appliance_url))

    conjur_authn_url = '{0}/authn'.format(appliance_url)
    identity = netrc(identity_path)

    if identity.authenticators(conjur_authn_url) is None:
        raise AnsibleError('The netrc file on the controlling host does not contain an entry for: {0}'
                           .format(conjur_authn_url))

    id, account, api_key = identity.authenticators(conjur_authn_url)
    if not id or not api_key:
        return {}

    return {'id': id, 'api_key': api_key}


# Merge multiple dictionaries by using dict.update mechanism
def _merge_dictionaries(*arg):
    ret = {}
    for item in arg:
        ret.update(item)
    return ret


# The `quote` method's default value for `safe` is '/' so it doesn't encode slashes
# into "%2F" which is what the Conjur server expects. Thus, we need to use this
# method with no safe characters. We can't use the method `quote_plus` (which encodes
# slashes correctly) because it encodes spaces into the character '+' instead of "%20"
# as expected by the Conjur server
def _encode_str(input_str):
    return quote(input_str, safe='')


# Use credentials to retrieve temporary authorization token
def _fetch_conjur_token(conjur_url, account, username, api_key, validate_certs, cert_file):
    conjur_url = '{0}/authn/{1}/{2}/authenticate'.format(conjur_url, account, _encode_str(username))
    display.vvvv('Authentication request to Conjur at: {0}, with user: {1}'.format(
        conjur_url,
        _encode_str(username)))

    response = open_url(conjur_url,
                        data=api_key,
                        method='POST',
                        validate_certs=validate_certs,
                        ca_path=cert_file)
    code = response.getcode()
    if code != 200:
        raise AnsibleError('Failed to authenticate as \'{0}\' (got {1} response)'
                           .format(username, code))

    return response.read()


def retry(retries, retry_interval):
    """
    Custom retry decorator

    Args:
        retries (int, optional): Number of retries. Defaults to 5.
        retry_interval (int, optional): Time to wait between intervals. Defaults to 10.
    """
    def parameters_wrapper(target):
        def decorator(*args, **kwargs):
            retry_count = 0
            while True:
                retry_count += 1
                try:
                    return_value = target(*args, **kwargs)
                    return return_value
                except urllib_error.HTTPError as e:
                    if retry_count >= retries:
                        raise e
                    display.v('Error encountered. Retrying..')
                except socket.timeout:
                    if retry_count >= retries:
                        raise e
                    display.v('Socket timeout encountered. Retrying..')
                sleep(retry_interval)
        return decorator
    return parameters_wrapper


@retry(retries=5, retry_interval=10)
def _repeat_open_url(url, headers=None, method=None, validate_certs=True, ca_path=None):
    return open_url(url,
                    headers=headers,
                    method=method,
                    validate_certs=validate_certs,
                    ca_path=ca_path)


# Retrieve Conjur variable using the temporary token
def _fetch_conjur_variable(conjur_variable, token, conjur_url, account, validate_certs, cert_file):
    token = b64encode(token)
    headers = {'Authorization': 'Token token="{0}"'.format(token.decode("utf-8"))}

    url = '{0}/secrets/{1}/variable/{2}'.format(conjur_url, account, _encode_str(conjur_variable))
    display.vvvv('Conjur Variable URL: {0}'.format(url))

    response = _repeat_open_url(url,
                                headers=headers,
                                method='GET',
                                validate_certs=validate_certs,
                                ca_path=cert_file)

    if response.getcode() == 200:
        display.vvvv('Conjur variable {0} was successfully retrieved'.format(conjur_variable))
        value = response.read().decode("utf-8")
        return [value]
    if response.getcode() == 401:
        raise AnsibleError('Conjur request has invalid authorization credentials')
    if response.getcode() == 403:
        raise AnsibleError('The controlling host\'s Conjur identity does not have authorization to retrieve {0}'
                           .format(conjur_variable))
    if response.getcode() == 404:
        raise AnsibleError('The variable {0} does not exist'.format(conjur_variable))

    return {}


def _default_tmp_path():
    if os.access("/dev/shm", os.W_OK):
        return "/dev/shm"

    return gettempdir()


def _store_secret_in_file(value):
    secrets_file = NamedTemporaryFile(mode='w', dir=_default_tmp_path(), delete=False)
    os.chmod(secrets_file.name, S_IRUSR | S_IWUSR)
    secrets_file.write(value[0])

    return [secrets_file.name]


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        if terms == []:
            raise AnsibleError("Invalid secret path: no secret path provided.")
        elif not terms[0] or terms[0].isspace():
            raise AnsibleError("Invalid secret path: empty secret path not accepted.")

        self.set_options(direct=kwargs)
        validate_certs = self.get_option('validate_certs')
        conf_file = self.get_option('config_file')
        as_file = self.get_option('as_file')

        if validate_certs is False:
            display.warning('Certificate validation has been disabled. Please enable with validate_certs option.')

        if 'http://' in str(environ.get("CONJUR_APPLIANCE_URL")):
            raise AnsibleError(('[WARNING]: Conjur URL uses insecure connection. Please consider using HTTPS.'))

        conf = _merge_dictionaries(
            _load_conf_from_file(conf_file),
            {
                "account": environ.get('CONJUR_ACCOUNT'),
                "appliance_url": environ.get("CONJUR_APPLIANCE_URL")
            } if (
                environ.get('CONJUR_ACCOUNT') is not None
                and environ.get('CONJUR_APPLIANCE_URL') is not None
            )
            else {},
            {
                "cert_file": environ.get('CONJUR_CERT_FILE')
            } if (environ.get('CONJUR_CERT_FILE') is not None)
            else {},
            {
                "authn_token_file": environ.get('CONJUR_AUTHN_TOKEN_FILE')
            } if (environ.get('CONJUR_AUTHN_TOKEN_FILE') is not None)
            else {}
        )

        if 'authn_token_file' not in conf:
            identity_file = self.get_option('identity_file')
            identity = _merge_dictionaries(
                _load_identity_from_file(identity_file, conf['appliance_url']),
                {
                    "id": environ.get('CONJUR_AUTHN_LOGIN'),
                    "api_key": environ.get('CONJUR_AUTHN_API_KEY')
                } if (environ.get('CONJUR_AUTHN_LOGIN') is not None
                      and environ.get('CONJUR_AUTHN_API_KEY') is not None)
                else {}
            )

            if 'account' not in conf or 'appliance_url' not in conf:
                raise AnsibleError(
                    ("Configuration file on the controlling host must "
                     "define `account` and `appliance_url`"
                     "entries or they should be environment variables")
                )

            if 'id' not in identity or 'api_key' not in identity:
                raise AnsibleError(
                    ("Identity file on the controlling host must contain "
                     "`login` and `password` entries for Conjur appliance"
                     " URL or they should be environment variables")
                )

        cert_file = None
        if 'cert_file' in conf:
            display.vvv("Using cert file path {0}".format(conf['cert_file']))
            cert_file = conf['cert_file']

        token = None
        if 'authn_token_file' not in conf:
            token = _fetch_conjur_token(
                conf['appliance_url'],
                conf['account'],
                identity['id'],
                identity['api_key'],
                validate_certs,
                cert_file
            )
        else:
            if not os.path.exists(conf['authn_token_file']):
                raise AnsibleError('Conjur authn token file `{0}` was not found on the host'
                                   .format(conf['authn_token_file']))
            with open(conf['authn_token_file'], 'rb') as f:
                token = f.read()

        conjur_variable = _fetch_conjur_variable(
            terms[0],
            token,
            conf['appliance_url'],
            conf['account'],
            validate_certs,
            cert_file
        )

        if as_file:
            return _store_secret_in_file(conjur_variable)

        return conjur_variable
