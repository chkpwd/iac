# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright (c), Jonathan Mainguy <jon@soh.re>, 2015
# Most of this was originally added by Sven Schliesing @muffl0n in the mysql_user.py module
#
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os

from ansible.module_utils.six.moves import configparser
from ansible.module_utils.basic import missing_required_lib

MYSQL_IMP_ERR = None
try:
    import pymysql as mysql_driver
    _mysql_cursor_param = 'cursor'
    HAS_MYSQL_PACKAGE = True
except ImportError:
    try:
        import MySQLdb as mysql_driver
        import MySQLdb.cursors
        _mysql_cursor_param = 'cursorclass'
        HAS_MYSQL_PACKAGE = True
    except ImportError:
        MYSQL_IMP_ERR = 'Cannot find PyMySQL or mysqlclient library.'
        HAS_MYSQL_PACKAGE = False
        mysql_driver = None


def parse_from_mysql_config_file(cnf):
    cp = configparser.ConfigParser()
    cp.read(cnf)
    return cp


def _version(cursor):
    cursor.execute("select version();")
    res = cursor.fetchone()

    # 2.2.0-72-ge14accd
    # 2.3.2-percona-1.1
    raw_version = res.get('version()').split('-', 1)
    _version = raw_version[0].split('.')

    version = dict()
    version['full'] = res.get('version()')
    version['major'] = int(_version[0])
    version['minor'] = int(_version[1])
    version['release'] = int(_version[2])
    version['suffix'] = raw_version[1]

    return version


def mysql_connect(module, login_user=None, login_password=None, config_file='', ssl_cert=None,
                  ssl_key=None, ssl_ca=None, db=None, cursor_class=None,
                  connect_timeout=30, autocommit=False, config_overrides_defaults=False):
    config = {}

    if not HAS_MYSQL_PACKAGE:
        module.fail_json(msg=missing_required_lib("pymysql or MySQLdb"), exception=MYSQL_IMP_ERR)

    if module.params["login_port"] < 0 \
       or module.params["login_port"] > 65535:
        module.fail_json(
            msg="login_port must be a valid unix port number (0-65535)"
        )

    if config_file and os.path.exists(config_file):
        config['read_default_file'] = config_file
        cp = parse_from_mysql_config_file(config_file)
        # Override some commond defaults with values from config file if needed
        if cp and cp.has_section('client') and config_overrides_defaults:
            try:
                module.params['login_host'] = cp.get('client', 'host', fallback=module.params['login_host'])
                module.params['login_port'] = cp.getint('client', 'port', fallback=module.params['login_port'])
            except Exception as e:
                if "got an unexpected keyword argument 'fallback'" in e.message:
                    module.fail_json('To use config_overrides_defaults, '
                                     'it needs Python 3.5+ as the default interpreter on a target host')

    if ssl_ca is not None or ssl_key is not None or ssl_cert is not None:
        config['ssl'] = {}

    if module.params['login_unix_socket']:
        config['unix_socket'] = module.params['login_unix_socket']
    else:
        config['host'] = module.params['login_host']
        config['port'] = module.params['login_port']

    # If login_user or login_password are given, they should override the
    # config file
    if login_user is not None:
        config['user'] = login_user
    if login_password is not None:
        config['passwd'] = login_password
    if ssl_cert is not None:
        config['ssl']['cert'] = ssl_cert
    if ssl_key is not None:
        config['ssl']['key'] = ssl_key
    if ssl_ca is not None:
        config['ssl']['ca'] = ssl_ca
    if db is not None:
        config['db'] = db
    if connect_timeout is not None:
        config['connect_timeout'] = connect_timeout

    if _mysql_cursor_param == 'cursor':
        # In case of PyMySQL driver:
        db_connection = mysql_driver.connect(autocommit=autocommit, **config)
    else:
        # In case of MySQLdb driver
        db_connection = mysql_driver.connect(**config)
        if autocommit:
            db_connection.autocommit(True)

    version = _version(db_connection.cursor(**{_mysql_cursor_param: mysql_driver.cursors.DictCursor}))

    if cursor_class == 'DictCursor':
        return (db_connection.cursor(**{_mysql_cursor_param: mysql_driver.cursors.DictCursor}),
                db_connection,
                version)
    else:
        return (db_connection.cursor(),
                db_connection,
                version)


def proxysql_common_argument_spec():
    return dict(
        login_user=dict(type='str', default=None),
        login_password=dict(type='str', no_log=True),
        login_host=dict(type='str', default='127.0.0.1'),
        login_port=dict(type='int', default=6032),
        login_unix_socket=dict(type='str'),
        config_file=dict(type='path', default=''),
    )


def save_config_to_disk(cursor, save_what, variable=None):
    if variable and variable.startswith("admin"):
        config_type = "ADMIN"
    elif save_what == "SCHEDULER":
        config_type = ""
    else:
        config_type = "MYSQL"

    cursor.execute("SAVE {0} {1} TO DISK".format(config_type, save_what))

    return True


def load_config_to_runtime(cursor, save_what, variable=None):
    if variable and variable.startswith("admin"):
        config_type = "ADMIN"
    elif save_what == "SCHEDULER":
        config_type = ""
    else:
        config_type = "MYSQL"

    cursor.execute("LOAD {0} {1} TO RUNTIME".format(config_type, save_what))

    return True
