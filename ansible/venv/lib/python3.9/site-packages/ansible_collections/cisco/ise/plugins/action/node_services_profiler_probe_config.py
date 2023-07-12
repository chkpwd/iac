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
    ise_compare_equality,
    ise_compare_equality2,
    get_dict_result,
)
from ansible_collections.cisco.ise.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = ise_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present"]),
    activeDirectory=dict(type="dict"),
    dhcp=dict(type="dict"),
    dhcpSpan=dict(type="dict"),
    dns=dict(type="dict"),
    http=dict(type="dict"),
    netflow=dict(type="dict"),
    nmap=dict(type="list"),
    pxgrid=dict(type="list"),
    radius=dict(type="list"),
    snmpQuery=dict(type="dict"),
    snmpTrap=dict(type="dict"),
    hostname=dict(type="str"),
))

required_if = [
    ("state", "present", ["hostname"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NodeServicesProfilerProbeConfig(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            active_directory=params.get("activeDirectory"),
            dhcp=params.get("dhcp"),
            dhcp_span=params.get("dhcpSpan"),
            dns=params.get("dns"),
            http=params.get("http"),
            netflow=params.get("netflow"),
            nmap=params.get("nmap"),
            pxgrid=params.get("pxgrid"),
            radius=params.get("radius"),
            snmp_query=params.get("snmpQuery"),
            snmp_trap=params.get("snmpTrap"),
            hostname=params.get("hostname"),
        )

    def get_object_by_name(self, name):
        try:
            result = self.ise.exec(
                family="node_services",
                function="get_profiler_probe_config",
                params={"hostname": name},
                handle_func_exception=False,
            ).response['response']
            result = get_dict_result(result, 'name', name)
        except (TypeError, AttributeError) as e:
            self.ise.fail_json(
                msg=(
                    "An error occured when executing operation."
                    " Check the configuration of your API Settings and API Gateway settings on your ISE server."
                    " This collection assumes that the API Gateway, the ERS APIs and OpenAPIs are enabled."
                    " You may want to enable the (ise_debug: True) argument."
                    " The error was: {error}"
                ).format(error=e)
            )
        except Exception:
            result = None
        return result

    def get_object_by_id(self, id):
        # NOTICE: Does not have a get by id method or it is in another action
        result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get("id")
        name = self.new_object.get("hostname")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters("The 'id' and 'name' params don't refer to the same object")
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("activeDirectory", "active_directory", False),
            ("dhcp", "dhcp", False),
            ("dhcpSpan", "dhcp_span", False),
            ("dns", "dns", False),
            ("http", "http", False),
            ("netflow", "netflow", False),
            ("nmap", "nmap", False),
            ("pxgrid", "pxgrid", False),
            ("radius", "radius", False),
            ("snmpQuery", "snmp_query", False),
            ("snmpTrap", "snmp_trap", False),
            ("hostname", "hostname", True),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality2(current_obj.get(ise_param),
                                             requested_obj.get(ansible_param),
                                             is_query_param)
                   for (ise_param, ansible_param, is_query_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("hostname")
        result = None
        if not name:
            name_ = self.get_object_by_id(id).get("hostname")
            self.new_object.update(dict(name=name_))
        result = self.ise.exec(
            family="node_services",
            function="set_profiler_probe_config",
            params=self.new_object
        ).response
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail("ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
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

        ise = ISESDK(params=self._task.args)
        obj = NodeServicesProfilerProbeConfig(self._task.args, ise)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    ise_update_response = obj.update()
                    self._result.update(dict(ise_update_response=ise_update_response))
                    (obj_exists, updated_obj) = obj.exists()
                    response = updated_obj
                    ise.object_updated()
                else:
                    response = prev_obj
                    ise.object_already_present()
            else:
                ise.fail_json("Object does not exists, plugin only has update")

        self._result.update(dict(ise_response=response))
        self._result.update(ise.exit_json())
        return self._result
