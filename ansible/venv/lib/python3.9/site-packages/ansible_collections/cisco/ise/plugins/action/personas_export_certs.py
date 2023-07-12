#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.plugins.action import ActionBase

try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from urllib.parse import quote
import time
from ansible_collections.cisco.ise.plugins.plugin_utils.personas_utils import Node

argument_spec = dict(
    primary_ip=dict(type="str", required=True),
    primary_username=dict(type="str", required=True),
    primary_password=dict(type="str", required=True),
    name=dict(type="str", required=True),
    ip=dict(type="str", required=True),
    hostname=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True),
    ise_verify=dict(type="bool", default=True),
    ise_version=dict(type="str", default="3.1.0"),
    ise_wait_on_rate_limit=dict(type="bool", default=True),
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'"
            )
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        primary_node = Node(dict(ip=self._task.args.get("primary_ip"),
                                 username=self._task.args.get("primary_username"),
                                 password=self._task.args.get("primary_password"),
                                 )
                            )

        this_node = Node(dict(name=self._task.args.get("name"),
                              ip=self._task.args.get("ip"),
                              hostname=self._task.args.get("hostname"),
                              username=self._task.args.get("username"),
                              password=self._task.args.get("password"),
                              )
                         )

        this_node.import_certificate_into_primary(primary_node)

        response = "The certificate for {hostname} was exported successfully to the primary node".format(hostname=this_node.hostname)

        self._result.update(dict(ise_response=response))
        return self._result
