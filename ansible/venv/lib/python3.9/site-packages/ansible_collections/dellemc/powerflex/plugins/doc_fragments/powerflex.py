# Copyright: (c) 2020, Dell Technologies.
# Apache License version 2.0 (see MODULE-LICENSE or http://www.apache.org/licenses/LICENSE-2.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    # Documentation fragment for PowerFlex
    DOCUMENTATION = r'''
    options:
        hostname:
            required: true
            description:
            - IP or FQDN of the PowerFlex host.
            type: str
            aliases:
            - gateway_host
        username:
            type: str
            required: true
            description:
            - The username of the PowerFlex host.
        password:
            type: str
            required: true
            description:
            - The password of the PowerFlex host.
        validate_certs:
            type: bool
            default: true
            aliases:
            - verifycert
            description:
            - Boolean variable to specify whether or not to validate SSL
              certificate.
            - C(true) - Indicates that the SSL certificate should be verified.
            - C(false) - Indicates that the SSL certificate should not be
              verified.
        port:
            description:
            - Port number through which communication happens with PowerFlex
              host.
            type: int
            default: 443
        timeout:
            description:
            - Time after which connection will get terminated.
            - It is to be mentioned in seconds.
            type: int
            required: False
            default: 120
    requirements:
      - A Dell PowerFlex storage system version 3.5 or later.
      - Ansible-core 2.12 or later.
      - PyPowerFlex 1.6.0.
      - Python 3.9, 3.10 or 3.11.
    notes:
      - The modules present in the collection named as 'dellemc.powerflex'
        are built to support the Dell PowerFlex storage platform.
'''
