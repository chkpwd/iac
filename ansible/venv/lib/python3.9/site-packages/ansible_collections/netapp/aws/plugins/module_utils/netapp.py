# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2019, NetApp Ansible Team <ng-ansibleteam@netapp.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
netapp.py
Support methods and class for AWS CVS modules
'''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import logging
import time
from ansible.module_utils.basic import missing_required_lib

try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'

COLLECTION_VERSION = "21.7.0"

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


POW2_BYTE_MAP = dict(
    # Here, 1 kb = 1024
    bytes=1,
    b=1,
    kb=1024,
    mb=1024 ** 2,
    gb=1024 ** 3,
    tb=1024 ** 4,
    pb=1024 ** 5,
    eb=1024 ** 6,
    zb=1024 ** 7,
    yb=1024 ** 8
)

LOG = logging.getLogger(__name__)
LOG_FILE = '/tmp/aws_cvs_apis.log'


def aws_cvs_host_argument_spec():

    return dict(
        api_url=dict(required=True, type='str'),
        validate_certs=dict(required=False, type='bool', default=True),
        api_key=dict(required=True, type='str', no_log=True),
        secret_key=dict(required=True, type='str', no_log=True),
        feature_flags=dict(required=False, type='dict', default=dict()),
    )


def has_feature(module, feature_name):
    feature = get_feature(module, feature_name)
    if isinstance(feature, bool):
        return feature
    module.fail_json(msg="Error: expected bool type for feature flag: %s" % feature_name)


def get_feature(module, feature_name):
    ''' if the user has configured the feature, use it
        otherwise, use our default
    '''
    default_flags = dict(
        strict_json_check=True,                 # if true, fail if response.content in not empty and is not valid json
        trace_apis=False,                       # if true, append REST requests/responses to LOG_FILE
    )

    if module.params['feature_flags'] is not None and feature_name in module.params['feature_flags']:
        return module.params['feature_flags'][feature_name]
    if feature_name in default_flags:
        return default_flags[feature_name]
    module.fail_json(msg="Internal error: unexpected feature flag: %s" % feature_name)


class AwsCvsRestAPI(object):
    ''' wraps requests methods to interface with AWS CVS REST APIs '''
    def __init__(self, module, timeout=60):
        self.module = module
        self.api_key = self.module.params['api_key']
        self.secret_key = self.module.params['secret_key']
        self.api_url = self.module.params['api_url']
        self.verify = self.module.params['validate_certs']
        self.timeout = timeout
        self.url = 'https://' + self.api_url + '/v1/'
        self.errors = list()
        self.debug_logs = list()
        self.check_required_library()
        if has_feature(module, 'trace_apis'):
            logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')

    def check_required_library(self):
        if not HAS_REQUESTS:
            self.module.fail_json(msg=missing_required_lib('requests'))

    def send_request(self, method, api, params, json=None):
        ''' send http request and process reponse, including error conditions '''
        if params is not None:
            self.module.fail_json(msg='params is not implemented.  api=%s, params=%s' % (api, repr(params)))
        url = self.url + api
        status_code = None
        content = None
        json_dict = None
        json_error = None
        error_details = None
        headers = {
            'Content-type': "application/json",
            'api-key': self.api_key,
            'secret-key': self.secret_key,
            'Cache-Control': "no-cache",
        }

        def check_contents(response):
            '''json() may fail on an empty value, but it's OK if no response is expected.
               To avoid false positives, only report an issue when we expect to read a value.
               The first get will see it.
            '''
            if method == 'GET' and has_feature(self.module, 'strict_json_check'):
                contents = response.content
                if len(contents) > 0:
                    raise ValueError("Expecting json, got: %s" % contents)

        def get_json(response):
            ''' extract json, and error message if present '''
            error = None
            try:
                json = response.json()
            except ValueError:
                check_contents(response)
                return None, None
            success_code = [200, 201, 202]
            if response.status_code not in success_code:
                error = json.get('message')
            return json, error

        def sanitize(value, key=None):
            if isinstance(value, dict):
                new_dict = dict()
                for key, value in value.items():
                    new_dict[key] = sanitize(value, key)
                return new_dict
            else:
                if key in ['api-key', 'secret-key', 'password']:
                    return '*' * 12
                else:
                    return value

        self.log_debug('sending', repr(sanitize(dict(method=method, url=url, verify=self.verify, params=params,
                                                     timeout=self.timeout, json=json, headers=headers))))
        try:
            response = requests.request(method, url, headers=headers, timeout=self.timeout, json=json)
            content = response.content  # for debug purposes
            status_code = response.status_code
            # If the response was successful, no Exception will be raised
            response.raise_for_status()
            json_dict, json_error = get_json(response)
        except requests.exceptions.HTTPError as err:
            __, json_error = get_json(response)
            if json_error is None:
                self.log_error(status_code, 'HTTP error: %s' % err)
                error_details = str(err)
            # If an error was reported in the json payload, it is handled below
        except requests.exceptions.ConnectionError as err:
            self.log_error(status_code, 'Connection error: %s' % err)
            error_details = str(err)
        except Exception as err:
            self.log_error(status_code, 'Other error: %s' % err)
            error_details = 'general exception: %s' % str(err)
        if json_error is not None:
            self.log_error(status_code, 'Endpoint error: %d: %s' % (status_code, json_error))
            error_details = json_error
        self.log_debug(status_code, content)
        return json_dict, error_details

    def get(self, api, params=None):
        method = 'GET'
        return self.send_request(method, api, params)

    def post(self, api, data, params=None):
        method = 'POST'
        return self.send_request(method, api, params, json=data)

    def patch(self, api, data, params=None):
        method = 'PATCH'
        return self.send_request(method, api, params, json=data)

    def put(self, api, data, params=None):
        method = 'PUT'
        return self.send_request(method, api, params, json=data)

    def delete(self, api, data, params=None):
        method = 'DELETE'
        return self.send_request(method, api, params, json=data)

    def get_state(self, job_id):
        """ Method to get the state of the job """
        response, dummy = self.get('Jobs/%s' % job_id)
        while str(response['state']) == 'ongoing':
            time.sleep(15)
            response, dummy = self.get('Jobs/%s' % job_id)
        return str(response['state'])

    def log_error(self, status_code, message):
        LOG.error("%s: %s", status_code, message)
        self.errors.append(message)
        self.debug_logs.append((status_code, message))

    def log_debug(self, status_code, content):
        LOG.debug("%s: %s", status_code, content)
        self.debug_logs.append((status_code, content))
