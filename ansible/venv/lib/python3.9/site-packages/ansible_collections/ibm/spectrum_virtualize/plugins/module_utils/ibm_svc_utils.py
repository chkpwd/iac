# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Support class for IBM SVC ansible modules """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import json
import logging

from ansible.module_utils.urls import open_url
from ansible.module_utils.six.moves.urllib.parse import quote
from ansible.module_utils.six.moves.urllib.error import HTTPError


def svc_argument_spec():
    """
    Returns argument_spec of options common to ibm_svc_*-modules

    :returns: argument_spec
    :rtype: dict
    """
    return dict(
        clustername=dict(type='str', required=True),
        domain=dict(type='str', default=None),
        validate_certs=dict(type='bool', default=False),
        username=dict(type='str'),
        password=dict(type='str', no_log=True),
        log_path=dict(type='str'),
        token=dict(type='str', no_log=True)
    )


def svc_ssh_argument_spec():
    """
    Returns argument_spec of options common to ibm_svcinfo_command
    and ibm_svctask_command modules

    :returns: argument_spec
    :rtype: dict
    """
    return dict(
        clustername=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        log_path=dict(type='str')
    )


def strtobool(val):
    '''
    Converts a string representation to boolean.

    This is a built-in function available in python till the version 3.9 under disutils.util
    but this has been deprecated in 3.10 and may not be available in future python releases
    so adding the source code here.
    '''
    if val in {'y', 'yes', 't', 'true', 'on', '1'}:
        return 1
    elif val in {'n', 'no', 'f', 'false', 'off', '0'}:
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))


def get_logger(module_name, log_file_name, log_level=logging.INFO):
    FORMAT = '%(asctime)s.%(msecs)03d %(levelname)5s %(thread)d %(filename)s:%(funcName)s():%(lineno)s %(message)s'
    DATEFORMAT = '%Y-%m-%dT%H:%M:%S'
    log_path = 'IBMSV_ansible_collections.log'
    if log_file_name:
        log_path = log_file_name
    logging.basicConfig(filename=log_path, format=FORMAT, datefmt=DATEFORMAT)
    log = logging.getLogger(module_name)
    log.setLevel(log_level)
    return log


class IBMSVCRestApi(object):
    """ Communicate with SVC through RestApi
    SVC commands usually have the format
    $ command -opt1 value1 -opt2 value2 arg1 arg2 arg3
    to use the RestApi we transform this into
    https://host:7443/rest/command/arg1/arg2/arg3
    data={'opt1':'value1', 'opt2':'value2'}
    """

    def __init__(self, module, clustername, domain, username, password,
                 validate_certs, log_path, token):
        """ Initialize module with what we need for initial connection
        :param clustername: name of the SVC cluster
        :type clustername: string
        :param domain: domain name to make a fully qualified host name
        :type domain: string
        :param username: SVC username
        :type username: string
        :param password: Password for user
        :type password: string
        :param validate_certs: whether or not the connection is insecure
        :type validate_certs: bool
        """
        self.module = module
        self.clustername = clustername
        self.domain = domain
        self.username = username
        self.password = password
        self.validate_certs = validate_certs
        self.token = token

        # logging setup
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Make sure we can connect through the RestApi
        if self.token is None:
            if not self.username or not self.password:
                self.module.fail_json(msg="You must pass in either pre-acquired token"
                                          " or username/password to generate new token")
            self.token = self._svc_authorize()
        else:
            self.log("Token already passed: %s", self.token)

        if not self.token:
            self.module.exit_json(msg='Failed to obtain access token', unreachable=True)

    @property
    def port(self):
        return getattr(self, '_port', None) or '7443'

    @property
    def protocol(self):
        return getattr(self, '_protocol', None) or 'https'

    @property
    def resturl(self):
        if self.domain:
            hostname = '%s.%s' % (self.clustername, self.domain)
        else:
            hostname = self.clustername
        return (getattr(self, '_resturl', None)
                or "{protocol}://{host}:{port}/rest".format(
                    protocol=self.protocol, host=hostname, port=self.port))

    @property
    def token(self):
        return getattr(self, '_token', None) or None

    @token.setter
    def token(self, value):
        return setattr(self, '_token', value)

    def _svc_rest(self, method, headers, cmd, cmdopts, cmdargs, timeout=10):
        """ Run SVC command with token info added into header
        :param method: http method, POST or GET
        :type method: string
        :param headers: http headers
        :type headers: dict
        :param cmd: svc command to run
        :type cmd: string
        :param cmdopts: svc command options, name paramter and value
        :type cmdopts: dict
        :param cmdargs: svc command arguments, non-named paramaters
        :type timeout: int
        :param timeout: open_url argument to set timeout for http gateway
        :return: dict of command results
        :rtype: dict
        """

        # Catch any output or errors and pass back to the caller to deal with.
        r = {
            'url': None,
            'code': None,
            'err': None,
            'out': None,
            'data': None
        }

        postfix = cmd
        if cmdargs:
            postfix = '/'.join([postfix] + [quote(str(a)) for a in cmdargs])
        url = '/'.join([self.resturl] + [postfix])
        r['url'] = url  # Pass back in result for error handling
        self.log("_svc_rest: url=%s", url)

        payload = cmdopts if cmdopts else None
        data = self.module.jsonify(payload).encode('utf8')
        r['data'] = cmdopts  # Original payload data has nicer formatting
        self.log("_svc_rest: payload=%s", payload)

        try:
            o = open_url(url, method=method, headers=headers, timeout=timeout,
                         validate_certs=self.validate_certs, data=bytes(data))
        except HTTPError as e:
            self.log('_svc_rest: httperror %s', str(e))
            r['code'] = e.getcode()
            r['out'] = e.read()
            r['err'] = "HTTPError %s", str(e)
            return r
        except Exception as e:
            self.log('_svc_rest: exception : %s', str(e))
            r['err'] = "Exception %s", str(e)
            return r

        try:
            j = json.load(o)
        except ValueError as e:
            self.log("_svc_rest: value error pass: %s", str(e))
            # pass, will mean both data and error are None.
            return r

        r['out'] = j
        return r

    def _svc_authorize(self):
        """ Obtain a token if we are authoized to connect
        :return: None or token string
        """

        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Username': self.username,
            'X-Auth-Password': self.password
        }

        rest = self._svc_rest(method='POST', headers=headers, cmd='auth',
                              cmdopts=None, cmdargs=None)

        if rest['err']:
            return None

        out = rest['out']
        if out:
            if 'token' in out:
                return out['token']

        return None

    def _svc_token_wrap(self, cmd, cmdopts, cmdargs, timeout=10):
        """ Run SVC command with token info added into header
        :param cmd: svc command to run
        :type cmd: string
        :param cmdopts: svc command options, name paramter and value
        :type cmdopts: dict
        :param cmdargs: svc command arguments, non-named paramaters
        :type cmdargs: list
        :param timeout: open_url argument to set timeout for http gateway
        :type timeout: int
        :returns: command results
        """

        if self.token is None:
            self.module.fail_json(msg="No authorize token")
            # Abort

        headers = {
            'Content-Type': 'application/json',
            'X-Auth-Token': self.token
        }

        return self._svc_rest(method='POST', headers=headers, cmd=cmd,
                              cmdopts=cmdopts, cmdargs=cmdargs, timeout=timeout)

    def svc_run_command(self, cmd, cmdopts, cmdargs, timeout=10):
        """ Generic execute a SVC command
        :param cmd: svc command to run
        :type cmd: string
        :param cmdopts: svc command options, name parameter and value
        :type cmdopts: dict
        :param cmdargs: svc command arguments, non-named parameters
        :type cmdargs: list
        :param timeout: open_url argument to set timeout for http gateway
        :type timeout: int
        :returns: command output
        """

        rest = self._svc_token_wrap(cmd, cmdopts, cmdargs, timeout)
        self.log("svc_run_command rest=%s", rest)

        if rest['err']:
            msg = rest
            self.module.fail_json(msg=msg)
            # Aborts

        # Might be None
        return rest['out']

    def svc_obj_info(self, cmd, cmdopts, cmdargs, timeout=10):
        """ Obtain information about an SVC object through the ls command
        :param cmd: svc command to run
        :type cmd: string
        :param cmdopts: svc command options, name parameter and value
        :type cmdopts: dict
        :param cmdargs: svc command arguments, non-named paramaters
        :type cmdargs: list
        :param timeout: open_url argument to set timeout for http gateway
        :type timeout: int
        :returns: command output
        :rtype: dict
        """

        rest = self._svc_token_wrap(cmd, cmdopts, cmdargs, timeout)
        self.log("svc_obj_info rest=%s", rest)

        if rest['code']:
            if rest['code'] == 500:
                # Object did not exist, which is quite valid.
                return None

        # Fail for anything else
        if rest['err']:
            self.module.fail_json(msg=rest)
            # Aborts

        # Might be None
        return rest['out']

    def get_auth_token(self):
        """ Obtain information about an SVC object through the ls command
        :returns: authentication token
        """
        # Make sure we can connect through the RestApi
        self.token = self._svc_authorize()
        self.log("_connect by using token")
        if not self.token:
            self.module.exit_json(msg='Failed to obtain access token', unreachable=True)

        return self.token
