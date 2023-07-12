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
from ansible_collections.cisco.ise.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = ise_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    name=dict(type="str"),
    description=dict(type="str"),
    stripPrefix=dict(type="bool"),
    stripSuffix=dict(type="bool"),
    prefixSeparator=dict(type="str"),
    suffixSeparator=dict(type="str"),
    remoteAccounting=dict(type="bool"),
    localAccounting=dict(type="bool"),
    useAttrSetOnRequest=dict(type="bool"),
    useAttrSetBeforeAcc=dict(type="bool"),
    continueAuthorzPolicy=dict(type="bool"),
    RadiusServerList=dict(type="list"),
    OnRequestAttrManipulatorList=dict(type="list"),
    BeforeAcceptAttrManipulatorsList=dict(type="list"),
    id=dict(type="str"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class RadiusServerSequence(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            name=params.get("name"),
            description=params.get("description"),
            strip_prefix=params.get("stripPrefix"),
            strip_suffix=params.get("stripSuffix"),
            prefix_separator=params.get("prefixSeparator"),
            suffix_separator=params.get("suffixSeparator"),
            remote_accounting=params.get("remoteAccounting"),
            local_accounting=params.get("localAccounting"),
            use_attr_set_on_request=params.get("useAttrSetOnRequest"),
            use_attr_set_before_acc=params.get("useAttrSetBeforeAcc"),
            continue_authorz_policy=params.get("continueAuthorzPolicy"),
            radius_server_list=params.get("RadiusServerList"),
            on_request_attr_manipulator_list=params.get("OnRequestAttrManipulatorList"),
            before_accept_attr_manipulators_list=params.get("BeforeAcceptAttrManipulatorsList"),
            id=params.get("id"),
        )

    def get_object_by_name(self, name):
        # NOTICE: Does not have a get by name method or it is in another action
        result = None
        gen_items_responses = self.ise.exec(
            family="radius_server_sequence",
            function="get_radius_server_sequence_generator"
        )
        try:
            for items_response in gen_items_responses:
                items = items_response.response['SearchResult']['resources']
                result = get_dict_result(items, 'name', name)
                if result:
                    return result
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
        return result

    def get_object_by_id(self, id):
        try:
            result = self.ise.exec(
                family="radius_server_sequence",
                function="get_radius_server_sequence_by_id",
                handle_func_exception=False,
                params={"id": id}
            ).response['RadiusServerSequence']
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
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("id")
        name = self.new_object.get("name")
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
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("name", "name"),
            ("description", "description"),
            ("stripPrefix", "strip_prefix"),
            ("stripSuffix", "strip_suffix"),
            ("prefixSeparator", "prefix_separator"),
            ("suffixSeparator", "suffix_separator"),
            ("remoteAccounting", "remote_accounting"),
            ("localAccounting", "local_accounting"),
            ("useAttrSetOnRequest", "use_attr_set_on_request"),
            ("useAttrSetBeforeAcc", "use_attr_set_before_acc"),
            ("continueAuthorzPolicy", "continue_authorz_policy"),
            ("RadiusServerList", "radius_server_list"),
            ("OnRequestAttrManipulatorList", "on_request_attr_manipulator_list"),
            ("BeforeAcceptAttrManipulatorsList", "before_accept_attr_manipulators_list"),
            ("id", "id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="radius_server_sequence",
            function="create_radius_server_sequence",
            params=self.new_object,
        ).response
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            id_ = self.get_object_by_name(name).get("id")
            self.new_object.update(dict(id=id_))
        result = self.ise.exec(
            family="radius_server_sequence",
            function="update_radius_server_sequence_by_id",
            params=self.new_object
        ).response
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            id_ = self.get_object_by_name(name).get("id")
            self.new_object.update(dict(id=id_))
        result = self.ise.exec(
            family="radius_server_sequence",
            function="delete_radius_server_sequence_by_id",
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
        obj = RadiusServerSequence(self._task.args, ise)

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
                    has_changed = None
                    has_changed = ise_update_response.get("UpdatedFieldsList").get("updatedField")
                    if (len(has_changed) == 0 or
                       has_changed[0].get("newValue") == "" and
                       has_changed[0].get("newValue") == has_changed[0].get("oldValue")):
                        self._result.pop("ise_update_response", None)
                        ise.object_already_present()
                    else:
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
