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
from ansible_collections.cisco.ise.plugins.plugin_utils.ise import (
    ISESDK,
    ise_argument_spec,
)

# Get common arguements specification
argument_spec = ise_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    name=dict(type="str"),
    id=dict(type="str"),
    page=dict(type="int"),
    size=dict(type="int"),
    sortasc=dict(type="str"),
    sortdsc=dict(type="str"),
    filter=dict(type="list"),
    filterType=dict(type="str"),
))

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail("ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = True
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

    def get_object(self, params):
        if params.get("name"):
            params["name"] = params["name"].replace('#', ':')
        new_object = dict(
            name=params.get("name"),
            id=params.get("id"),
            page=params.get("page"),
            size=params.get("size"),
            sortasc=params.get("sortasc"),
            sortdsc=params.get("sortdsc"),
            filter=params.get("filter"),
            filter_type=params.get("filterType"),
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        self._result.update(dict(ise_response=[]))

        ise = ISESDK(params=self._task.args)

        id = self._task.args.get("id")
        name = self._task.args.get("name")
        if id:
            response = ise.exec(
                family="network_device_group",
                function='get_network_device_group_by_id',
                params=self.get_object(self._task.args)
            ).response['NetworkDeviceGroup']
            self._result.update(dict(ise_response=response))
            self._result.update(ise.exit_json())
            return self._result
        if name:
            response = ise.exec(
                family="network_device_group",
                function='get_network_device_group_by_name',
                params=self.get_object(self._task.args)
            ).response['NetworkDeviceGroup']
            self._result.update(dict(ise_response=response))
            self._result.update(ise.exit_json())
            return self._result
        if not name and not id:
            responses = []
            generator = ise.exec(
                family="network_device_group",
                function='get_network_device_group_generator',
                params=self.get_object(self._task.args),
            )
            try:
                for item in generator:
                    tmp_response = item.response['SearchResult']['resources']
                    if isinstance(tmp_response, list):
                        responses += tmp_response
                    else:
                        responses.append(tmp_response)
                response = responses
            except (TypeError, AttributeError) as e:
                ise.fail_json(
                    msg=(
                        "An error occured when executing operation."
                        " Check the configuration of your API Settings and API Gateway settings on your ISE server."
                        " This collection assumes that the API Gateway, the ERS APIs and OpenAPIs are enabled."
                        " You may want to enable the (ise_debug: True) argument."
                        " The error was: {error}"
                    ).format(error=e)
                )
            except Exception as e:
                ise.fail_json(
                    msg=(
                        "An error occured when executing operation."
                        " The error was: {error}"
                        " You may want to enable the (ise_debug: True) argument."
                    ).format(error=e)
                )

            self._result.update(dict(ise_response=response))
            self._result.update(ise.exit_json())
            return self._result
