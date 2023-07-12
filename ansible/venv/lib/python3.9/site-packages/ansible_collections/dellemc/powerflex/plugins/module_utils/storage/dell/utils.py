# Copyright: (c) 2021, Dell Technologies
# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import logging
import math
import re
from decimal import Decimal
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell.logging_handler \
    import CustomRotatingFileHandler
import traceback
from ansible.module_utils.basic import missing_required_lib

"""import PyPowerFlex lib"""
try:
    from PyPowerFlex import PowerFlexClient
    from PyPowerFlex.objects.sds import Sds
    from PyPowerFlex.objects import protection_domain
    from PyPowerFlex.objects import storage_pool
    from PyPowerFlex.objects import sdc
    from PyPowerFlex.objects import volume
    from PyPowerFlex.objects import system
    from PyPowerFlex.objects.system import SnapshotDef

    HAS_POWERFLEX_SDK, POWERFLEX_SDK_IMP_ERR = True, None
except ImportError:
    HAS_POWERFLEX_SDK, POWERFLEX_SDK_IMP_ERR = False, traceback.format_exc()

"""importing pkg_resources"""
try:
    from pkg_resources import parse_version
    import pkg_resources

    PKG_RSRC_IMPORTED, PKG_RSRC_IMP_ERR = True, None
except ImportError:
    PKG_RSRC_IMPORTED, PKG_RSRC_IMP_ERR = False, traceback.format_exc()

"""importing dateutil"""
try:
    import dateutil.relativedelta
    HAS_DATEUTIL, DATEUTIL_IMP_ERR = True, None
except ImportError:
    HAS_DATEUTIL, DATEUTIL_IMP_ERR = False, traceback.format_exc()


def get_powerflex_gateway_host_parameters():
    """Provides common access parameters required for the
    ansible modules on PowerFlex Storage System"""

    return dict(
        hostname=dict(type='str', aliases=['gateway_host'], required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        validate_certs=dict(type='bool', aliases=['verifycert'], required=False, default=True),
        port=dict(type='int', required=False, default=443),
        timeout=dict(type='int', required=False, default=120)
    )


def get_powerflex_gateway_host_connection(module_params):
    """Establishes connection with PowerFlex storage system"""

    if HAS_POWERFLEX_SDK:
        conn = PowerFlexClient(
            gateway_address=module_params['hostname'],
            gateway_port=module_params['port'],
            verify_certificate=module_params['validate_certs'],
            username=module_params['username'],
            password=module_params['password'],
            timeout=module_params['timeout'])
        conn.initialize()
        return conn


def ensure_required_libs(module):
    """Check required libraries"""

    if not HAS_DATEUTIL:
        module.fail_json(msg=missing_required_lib("python-dateutil"),
                         exception=DATEUTIL_IMP_ERR)

    if not PKG_RSRC_IMPORTED:
        module.fail_json(msg=missing_required_lib("pkg_resources"),
                         exception=PKG_RSRC_IMP_ERR)

    if not HAS_POWERFLEX_SDK:
        module.fail_json(msg=missing_required_lib("PyPowerFlex V 1.6.0 or above"),
                         exception=POWERFLEX_SDK_IMP_ERR)

    min_ver = '1.6.0'
    try:
        curr_version = pkg_resources.require("PyPowerFlex")[0].version
        supported_version = (parse_version(curr_version) >= parse_version(min_ver))
        if not supported_version:
            module.fail_json(msg="PyPowerFlex {0} is not supported. "
                             "Required minimum version is "
                             "{1}".format(curr_version, min_ver))
    except Exception as e:
        module.fail_json(msg="Getting PyPowerFlex SDK version, failed with "
                             "Error {0}".format(str(e)))


def get_logger(module_name, log_file_name='ansible_powerflex.log', log_devel=logging.INFO):
    """
    Initialize logger and return the logger object.
    :param module_name: Name of module to be part of log message
    :param log_file_name: Name of file in which the log messages get appended
    :param log_devel: Log level
    :return LOG object
    """
    FORMAT = '%(asctime)-15s %(filename)s %(levelname)s : %(message)s'
    max_bytes = 5 * 1024 * 1024
    logging.basicConfig(filename=log_file_name, format=FORMAT)
    LOG = logging.getLogger(module_name)
    LOG.setLevel(log_devel)
    handler = CustomRotatingFileHandler(log_file_name, maxBytes=max_bytes, backupCount=5)
    formatter = logging.Formatter(FORMAT)
    handler.setFormatter(formatter)
    LOG.addHandler(handler)
    LOG.propagate = False
    return LOG


KB_IN_BYTES = 1024
MB_IN_BYTES = 1024 * 1024
GB_IN_BYTES = 1024 * 1024 * 1024
TB_IN_BYTES = 1024 * 1024 * 1024 * 1024


def get_size_bytes(size, cap_units):
    """Convert the given size to bytes"""

    if size is not None and size > 0:
        if cap_units in ('kb', 'KB'):
            return size * KB_IN_BYTES
        elif cap_units in ('mb', 'MB'):
            return size * MB_IN_BYTES
        elif cap_units in ('gb', 'GB'):
            return size * GB_IN_BYTES
        elif cap_units in ('tb', 'TB'):
            return size * TB_IN_BYTES
        else:
            return size
    else:
        return 0


def convert_size_with_unit(size_bytes):
    """Convert size in byte with actual unit like KB,MB,GB,TB,PB etc."""

    if not isinstance(size_bytes, int):
        raise ValueError('This method takes Integer type argument only')
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def get_size_in_gb(size, cap_units):
    """Convert the given size to size in GB, size is restricted to 2 decimal places"""

    size_in_bytes = get_size_bytes(size, cap_units)
    size = Decimal(size_in_bytes / GB_IN_BYTES)
    size_in_gb = round(size)
    return size_in_gb


def is_version_less_than_3_6(version):
    """Verifies if powerflex version is less than 3.6"""
    version = re.search(r'R\s*([\d.]+)', version.replace('_', '.')).group(1)
    return \
        pkg_resources.parse_version(version) < pkg_resources.parse_version('3.6')


def is_invalid_name(name):
    """Validates string against regex pattern"""
    if name is not None:
        regexp = re.compile(r'^[a-zA-Z0-9!@#$%^~*_-]*$')
        if not regexp.search(name):
            return True
