# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2017, Sumit Kumar <sumit4@netapp.com>
# Copyright (c) 2017, Michael Price <michael.price@netapp.com>
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
common routines for um_info
'''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import logging
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils._text import to_native

try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'

COLLECTION_VERSION = "21.8.0"

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

ERROR_MSG = dict(
    no_cserver='This module is expected to run as cluster admin'
)

LOG = logging.getLogger(__name__)
LOG_FILE = '/tmp/um_apis.log'


def na_um_host_argument_spec():

    return dict(
        hostname=dict(required=True, type='str'),
        username=dict(required=True, type='str'),
        password=dict(required=True, type='str', no_log=True),
        validate_certs=dict(required=False, type='bool', default=True),
        http_port=dict(required=False, type='int'),
        feature_flags=dict(required=False, type='dict', default=dict()),
        max_records=dict(required=False, type='int')
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


class UMRestAPI(object):
    ''' send REST request and process response '''
    def __init__(self, module, timeout=60):
        self.module = module
        self.username = self.module.params['username']
        self.password = self.module.params['password']
        self.hostname = self.module.params['hostname']
        self.verify = self.module.params['validate_certs']
        self.max_records = self.module.params['max_records']
        self.timeout = timeout
        if self.module.params.get('http_port') is not None:
            self.url = 'https://%s:%d' % (self.hostname, self.module.params['http_port'])
        else:
            self.url = 'https://%s' % self.hostname
        self.errors = list()
        self.debug_logs = list()
        self.check_required_library()
        if has_feature(module, 'trace_apis'):
            logging.basicConfig(filename=LOG_FILE, level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')

    def check_required_library(self):
        if not HAS_REQUESTS:
            self.module.fail_json(msg=missing_required_lib('requests'))

    def get_records(self, message, api):
        records = list()
        try:
            if message['total_records'] > 0:
                records = message['records']
                if message['total_records'] != len(records):
                    self.module.warn('Mismatch between received: %d and expected: %d records.' % (len(records), message['total_records']))
        except KeyError as exc:
            self.module.fail_json(msg='Error: unexpected response from %s: %s - expecting key: %s'
                                  % (api, message, to_native(exc)))
        return records

    def send_request(self, method, api, params, json=None, accept=None):
        ''' send http request and process response, including error conditions '''
        url = self.url + api
        status_code = None
        content = None
        json_dict = None
        json_error = None
        error_details = None
        headers = None
        if accept is not None:
            headers = dict()
            # accept is used to turn on/off HAL linking
            if accept is not None:
                headers['accept'] = accept

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
            try:
                json = response.json()
            except ValueError:
                check_contents(response)
                return None, None
            error = json.get('error')
            return json, error

        self.log_debug('sending', repr(dict(method=method, url=url, verify=self.verify, params=params,
                                            timeout=self.timeout, json=json, headers=headers)))
        try:
            response = requests.request(method, url, verify=self.verify, auth=(self.username, self.password),
                                        params=params, timeout=self.timeout, json=json, headers=headers)
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
            error_details = str(err)
        if json_error is not None:
            self.log_error(status_code, 'Endpoint error: %d: %s' % (status_code, json_error))
            error_details = json_error
        self.log_debug(status_code, content)
        return json_dict, error_details

    def get(self, api, params):

        def get_next_api(message):
            '''make sure _links is present, and href is present if next is present
               return api if next is present, None otherwise
               return error if _links or href are missing
            '''
            api, error = None, None
            if message is None or '_links' not in message:
                error = 'Expecting _links key in %s' % message
            elif 'next' in message['_links']:
                if 'href' in message['_links']['next']:
                    api = message['_links']['next']['href']
                else:
                    error = 'Expecting href key in %s' % message['_links']['next']
            return api, error

        method = 'GET'
        records = list()
        if self.max_records is not None:
            if params and 'max_records' not in params:
                params['max_records'] = self.max_records
            else:
                params = dict(max_records=self.max_records)
        api = '/api/%s' % api

        while api:
            message, error = self.send_request(method, api, params)
            if error:
                return message, error
            api, error = get_next_api(message)
            if error:
                return message, error
            if 'records' in message:
                records.extend(message['records'])
            params = None       # already included in the next link

        if records:
            message['records'] = records
        return message, error

    def log_error(self, status_code, message):
        LOG.error("%s: %s", status_code, message)
        self.errors.append(message)
        self.debug_logs.append((status_code, message))

    def log_debug(self, status_code, content):
        LOG.debug("%s: %s", status_code, content)
        self.debug_logs.append((status_code, content))
