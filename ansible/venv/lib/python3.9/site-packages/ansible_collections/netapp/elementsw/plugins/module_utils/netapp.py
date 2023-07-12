# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c) 2017, Sumit Kumar <sumit4@netapp.com>
# Copyright (c) 2017, Michael Price <michael.price@netapp.com>
# Copyright: (c) 2018, NetApp Ansible Team <ng-ansibleteam@netapp.com>
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
Common methods and constants
'''

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

HAS_SF_SDK = False
SF_BYTE_MAP = dict(
    # Management GUI displays 1024 ** 3 as 1.1 GB, thus use 1000.
    bytes=1,
    b=1,
    kb=1000,
    mb=1000 ** 2,
    gb=1000 ** 3,
    tb=1000 ** 4,
    pb=1000 ** 5,
    eb=1000 ** 6,
    zb=1000 ** 7,
    yb=1000 ** 8
)

# uncomment this to log API calls
# import logging

try:
    from solidfire.factory import ElementFactory
    import solidfire.common
    HAS_SF_SDK = True
except ImportError:
    HAS_SF_SDK = False

COLLECTION_VERSION = "21.7.0"


def has_sf_sdk():
    return HAS_SF_SDK


def ontap_sf_host_argument_spec():

    return dict(
        hostname=dict(required=True, type='str'),
        username=dict(required=True, type='str', aliases=['user']),
        password=dict(required=True, type='str', aliases=['pass'], no_log=True)
    )


def create_sf_connection(module, hostname=None, port=None, raise_on_connection_error=False, timeout=None):
    if hostname is None:
        hostname = module.params['hostname']
    username = module.params['username']
    password = module.params['password']
    options = dict()
    if port is not None:
        options['port'] = port
    if timeout is not None:
        options['timeout'] = timeout

    if not HAS_SF_SDK:
        module.fail_json(msg="the python SolidFire SDK module is required")

    try:
        logging.basicConfig(filename='/tmp/elementsw_apis.log', level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s')
    except NameError:
        # logging was not imported
        pass

    try:
        return_val = ElementFactory.create(hostname, username, password, **options)
    except (solidfire.common.ApiConnectionError, solidfire.common.ApiServerError) as exc:
        if raise_on_connection_error:
            raise exc
        module.fail_json(msg=repr(exc))
    except Exception as exc:
        raise Exception("Unable to create SF connection: %s" % repr(exc))
    return return_val
