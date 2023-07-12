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
    get_dict_result,
)

# Get common arguments specification
argument_spec = ise_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    conditionType=dict(type="str"),
    isNegate=dict(type="bool"),
    link=dict(type="dict"),
    description=dict(type="str"),
    id=dict(type="str"),
    name=dict(type="str"),
    attributeName=dict(type="str"),
    attributeValue=dict(type="str"),
    dictionaryName=dict(type="str"),
    dictionaryValue=dict(type="str"),
    operator=dict(type="str"),
    children=dict(type="list"),
    datesRange=dict(type="dict"),
    datesRangeException=dict(type="dict"),
    hoursRange=dict(type="dict"),
    hoursRangeException=dict(type="dict"),
    weekDays=dict(type="list"),
    weekDaysException=dict(type="list"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworkAccessConditions(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            condition_type=params.get("conditionType"),
            is_negate=params.get("isNegate"),
            link=params.get("link"),
            description=params.get("description"),
            id=params.get("id"),
            name=params.get("name"),
            attribute_name=params.get("attributeName"),
            attribute_value=params.get("attributeValue"),
            dictionary_name=params.get("dictionaryName"),
            dictionary_value=params.get("dictionaryValue"),
            operator=params.get("operator"),
            children=params.get("children"),
            dates_range=params.get("datesRange"),
            dates_range_exception=params.get("datesRangeException"),
            hours_range=params.get("hoursRange"),
            hours_range_exception=params.get("hoursRangeException"),
            week_days=params.get("weekDays"),
            week_days_exception=params.get("weekDaysException"),
        )

    def get_object_by_name(self, name):
        try:
            result = self.ise.exec(
                family="network_access_conditions",
                function="get_network_access_condition_by_name",
                params={"name": name},
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
        try:
            result = self.ise.exec(
                family="network_access_conditions",
                function="get_network_access_condition_by_id",
                handle_func_exception=False,
                params={"id": id}
            ).response['response']
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

    def exists(self):
        result = False
        prev_obj = None
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        if id:
            prev_obj = self.get_object_by_id(id)
            result = prev_obj is not None and isinstance(prev_obj, dict)
        elif name:
            prev_obj = self.get_object_by_name(name)
            result = prev_obj is not None and isinstance(prev_obj, dict)
        return (result, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("conditionType", "condition_type"),
            ("isNegate", "is_negate"),
            ("link", "link"),
            ("description", "description"),
            ("id", "id"),
            ("name", "name"),
            ("attributeName", "attribute_name"),
            ("attributeValue", "attribute_value"),
            ("dictionaryName", "dictionary_name"),
            ("dictionaryValue", "dictionary_value"),
            ("operator", "operator"),
            ("children", "children"),
            ("datesRange", "dates_range"),
            ("datesRangeException", "dates_range_exception"),
            ("hoursRange", "hours_range"),
            ("hoursRangeException", "hours_range_exception"),
            ("weekDays", "week_days"),
            ("weekDaysException", "week_days_exception"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="network_access_conditions",
            function="create_network_access_condition",
            params=self.new_object,
        ).response
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if id:
            result = self.ise.exec(
                family="network_access_conditions",
                function="update_network_access_condition_by_id",
                params=self.new_object
            ).response
        elif name:
            result = self.ise.exec(
                family="network_access_conditions",
                function="update_network_access_condition_by_name",
                params=self.new_object
            ).response
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if id:
            result = self.ise.exec(
                family="network_access_conditions",
                function="delete_network_access_condition_by_id",
                params=self.new_object
            ).response
        elif name:
            result = self.ise.exec(
                family="network_access_conditions",
                function="delete_network_access_condition_by_name",
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
        obj = NetworkAccessConditions(self._task.args, ise)

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
                ise_create_response = obj.create()
                (obj_exists, created_obj) = obj.exists()
                response = created_obj
                ise.object_created()

        elif state == "absent":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                obj.delete()
                response = prev_obj
                ise.object_deleted()
            else:
                ise.object_already_absent()

        self._result.update(dict(ise_response=response))
        self._result.update(ise.exit_json())
        return self._result
