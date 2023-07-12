# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Infinidat <info@infinidat.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from ansible.module_utils.six import raise_from
try:
    import ansible.module_utils.errors
except (ImportError, ModuleNotFoundError):
    import errors  # Used during "make dev-hack-module-[present, stat, absent]"

try:
    from infinisdk import InfiniBox, core
    from infinisdk.core.exceptions import ObjectNotFound
except ImportError as imp_exc:
    HAS_INFINISDK = False
    INFINISDK_IMPORT_ERROR = imp_exc
else:
    HAS_INFINISDK = True
    INFINISDK_IMPORT_ERROR = None

from functools import wraps
from os import environ
from os import path
from datetime import datetime


def unixMillisecondsToDate(unix_ms):
    return (datetime.utcfromtimestamp(unix_ms / 1000.), 'UTC')


def api_wrapper(func):
    """ Catch API Errors Decorator"""
    @wraps(func)
    def __wrapper(*args, **kwargs):
        module = args[0]
        try:
            return func(*args, **kwargs)
        except core.exceptions.APICommandException as e:
            module.fail_json(msg=e.message)
        except core.exceptions.SystemNotFoundException as e:
            module.fail_json(msg=e.message)
        except Exception:
            raise
    return __wrapper


def infinibox_argument_spec():
    """Return standard base dictionary used for the argument_spec argument in AnsibleModule"""
    return dict(
        system=dict(required=True),
        user=dict(required=True),
        password=dict(required=True, no_log=True),
    )


def infinibox_required_together():
    """Return the default list used for the required_together argument to AnsibleModule"""
    return [['user', 'password']]


def merge_two_dicts(dict1, dict2):
    """
    Merge two dicts into one and return.
    result = {**dict1, **dict2} only works in py3.5+.
    """
    result = dict1.copy()
    result.update(dict2)
    return result


@api_wrapper
def get_system(module):
    """Return System Object or Fail"""
    box = module.params['system']
    user = module.params.get('user', None)
    password = module.params.get('password', None)

    if user and password:
        system = InfiniBox(box, auth=(user, password), use_ssl=True)
    elif environ.get('INFINIBOX_USER') and environ.get('INFINIBOX_PASSWORD'):
        system = InfiniBox(box,
                           auth=(environ.get('INFINIBOX_USER'),
                                 environ.get('INFINIBOX_PASSWORD')),
                           use_ssl=True)
    elif path.isfile(path.expanduser('~') + '/.infinidat/infinisdk.ini'):
        system = InfiniBox(box, use_ssl=True)
    else:
        module.fail_json(msg="You must set INFINIBOX_USER and INFINIBOX_PASSWORD environment variables or set username/password module arguments")

    try:
        system.login()
    except Exception:
        module.fail_json(msg="Infinibox authentication failed. Check your credentials")
    return system


@api_wrapper
def get_pool(module, system):
    """
    Return Pool. Try key look up using 'pool', or if that fails, 'name'.
    If the pool is not found, return None.
    """
    try:
        try:
            name = module.params['pool']
        except KeyError:
            name = module.params['name']
        return system.pools.get(name=name)
    except Exception:
        return None


@api_wrapper
def get_filesystem(module, system):
    """Return Filesystem or None"""
    try:
        try:
            filesystem = system.filesystems.get(name=module.params['filesystem'])
        except KeyError:
            filesystem = system.filesystems.get(name=module.params['name'])
        return filesystem
    except Exception:
        return None


@api_wrapper
def get_export(module, system):
    """Return export if found or None if not found"""
    try:
        try:
            export_name = module.params['export']
        except KeyError:
            export_name = module.params['name']

        export = system.exports.get(export_path=export_name)
    except ObjectNotFound as err:
        return None

    return export


@api_wrapper
def get_volume(module, system):
    """Return Volume or None"""
    try:
        try:
            volume = system.volumes.get(name=module.params['name'])
        except KeyError:
            volume = system.volumes.get(name=module.params['volume'])
        return volume
    except Exception:
        return None


@api_wrapper
def get_net_space(module, system):
    """Return network space or None"""
    try:
        net_space = system.network_spaces.get(name=module.params['name'])
    except (KeyError, ObjectNotFound):
        return None
    return net_space


@api_wrapper
def get_vol_sn(module, system):
    """Return Volume or None"""
    try:
        try:
            volume = system.volumes.get(serial=module.params['serial'])
        except KeyError:
            return None
        return volume
    except Exception:
        return None


@api_wrapper
def get_host(module, system):
    """Find a host by the name specified in the module"""
    host = None

    for a_host in system.hosts.to_list():
        a_host_name = a_host.get_name()
        try:
            host_param = module.params['name']
        except KeyError:
            host_param = module.params['host']

        if a_host_name == host_param:
            host = a_host
            break
    return host


@api_wrapper
def get_cluster(module, system):
    """Find a cluster by the name specified in the module"""
    cluster = None
    # print("dir:", dir(system))

    for a_cluster in system.host_clusters.to_list():
        a_cluster_name = a_cluster.get_name()
        try:
            cluster_param = module.params['name']
        except KeyError:
            cluster_param = module.params['cluster']

        if a_cluster_name == cluster_param:
            cluster = a_cluster
            break
    return cluster


@api_wrapper
def get_user(module, system):
    """Find a user by the user_name specified in the module"""
    user = None
    user_name = module.params['user_name']
    try:
        user = system.users.get(name=user_name)
    except ObjectNotFound:
        pass
    return user
