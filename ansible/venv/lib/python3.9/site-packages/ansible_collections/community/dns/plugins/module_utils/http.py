# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


import abc

from ansible.module_utils import six
from ansible.module_utils.common.text.converters import to_native
from ansible.module_utils.six import PY3
from ansible.module_utils.urls import fetch_url, open_url, urllib_error, NoSSLError, ConnectionError


class NetworkError(Exception):
    pass


@six.add_metaclass(abc.ABCMeta)
class HTTPHelper(object):
    @abc.abstractmethod
    def fetch_url(self, url, method='GET', headers=None, data=None, timeout=None):
        """
        Execute a HTTP request and return a tuple (response_content, info).

        In case of errors, either raise NetworkError or terminate the program (for modules only!).
        """


class ModuleHTTPHelper(HTTPHelper):
    def __init__(self, module):
        self.module = module

    def fetch_url(self, url, method='GET', headers=None, data=None, timeout=None):
        response, info = fetch_url(self.module, url, method=method, headers=headers, data=data, timeout=timeout)
        try:
            # In Python 2, reading from a closed response yields a TypeError.
            # In Python 3, read() simply returns ''
            if PY3 and response.closed:
                raise TypeError
            content = response.read()
        except (AttributeError, TypeError):
            content = info.pop('body', None)
        return content, info


class OpenURLHelper(HTTPHelper):
    def fetch_url(self, url, method='GET', headers=None, data=None, timeout=None):
        info = {}
        try:
            req = open_url(url, method=method, headers=headers, data=data, timeout=timeout)
            result = req.read()
            info.update(dict((k.lower(), v) for k, v in req.info().items()))
            info['status'] = req.code
            info['url'] = req.geturl()
            req.close()
        except urllib_error.HTTPError as e:
            try:
                result = e.read()
            except AttributeError:
                result = ''
            try:
                info.update(dict((k.lower(), v) for k, v in e.info().items()))
            except Exception:
                pass
            info['status'] = e.code
        except NoSSLError as e:
            raise NetworkError('Cannot connect via SSL: {0}'.format(to_native(e)))
        except (ConnectionError, ValueError) as e:
            raise NetworkError('Connection error: {0}'.format(to_native(e)))

        return result, info
