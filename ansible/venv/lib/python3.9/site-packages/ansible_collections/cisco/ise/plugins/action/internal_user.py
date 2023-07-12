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
try:
    from ciscoisesdk import exceptions
except ImportError:
    ISE_SDK_IS_INSTALLED = False
else:
    ISE_SDK_IS_INSTALLED = True
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
    name=dict(type="str"),
    description=dict(type="str"),
    enabled=dict(type="bool"),
    email=dict(type="str"),
    password=dict(type="str", no_log=True),
    firstName=dict(type="str"),
    lastName=dict(type="str"),
    changePassword=dict(type="bool"),
    identityGroups=dict(type="str"),
    expiryDateEnabled=dict(type="bool"),
    expiryDate=dict(type="str"),
    enablePassword=dict(type="str"),
    customAttributes=dict(type="dict"),
    passwordIDStore=dict(type="str"),
    id=dict(type="str"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class InternalUser(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            name=params.get("name"),
            description=params.get("description"),
            enabled=params.get("enabled"),
            email=params.get("email"),
            password=params.get("password"),
            first_name=params.get("firstName"),
            last_name=params.get("lastName"),
            change_password=params.get("changePassword"),
            identity_groups=params.get("identityGroups"),
            expiry_date_enabled=params.get("expiryDateEnabled"),
            expiry_date=params.get("expiryDate"),
            enable_password=params.get("enablePassword"),
            custom_attributes=params.get("customAttributes"),
            password_idstore=params.get("passwordIDStore"),
            id=params.get("id"),
        )

    def get_object_by_name(self, name):
        try:
            result = self.ise.exec(
                family="internal_user",
                function="get_internal_user_by_name",
                params={"name": name},
                handle_func_exception=False,
            ).response['InternalUser']
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
                family="internal_user",
                function="get_internal_user_by_id",
                params={"id": id},
                handle_func_exception=False,
            ).response['InternalUser']
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

        force_change = False
        change_params = [
            ("change_password", bool)
        ]
        for (change_param, type_) in change_params:
            requested_obj_value = requested_obj.get(change_param)
            if isinstance(requested_obj_value, type_):
                # Next line checks if value is evaluated as True
                if requested_obj_value:
                    force_change = True
                    break
                else:
                    pass
            else:
                pass

        if force_change:
            return force_change

        obj_params = [
            ("name", "name"),
            ("description", "description"),
            ("enabled", "enabled"),
            ("email", "email"),
            ("password", "password"),
            ("firstName", "first_name"),
            ("lastName", "last_name"),
            ("changePassword", "change_password"),
            ("identityGroups", "identity_groups"),
            ("expiryDateEnabled", "expiry_date_enabled"),
            ("expiryDate", "expiry_date"),
            ("enablePassword", "enable_password"),
            ("customAttributes", "custom_attributes"),
            ("passwordIDStore", "password_idstore"),
            ("id", "id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="internal_user",
            function="create_internal_user",
            params=self.new_object,
        ).response
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        change_password = self.new_object.get("change_password")
        result = None
        if id:
            try:
                result = self.ise.exec(
                    family="internal_user",
                    function="update_internal_user_by_id",
                    params=self.new_object,
                    handle_func_exception=False,
                ).response
            except exceptions.ApiError as e:
                if not change_password and "Password can't be set to one of the earlier" in e.message:
                    self.ise.object_modify_result(changed=False, result="Object already present, update was attempted but failed because of password")
                    result = {'_changed_': True}
                elif not change_password and "Password can't be set to one of the earlier" in e.details_str:
                    self.ise.object_modify_result(changed=False, result="Object already present, update was attempted but failed because of password")
                    result = {'_changed_': True}
                else:
                    raise e
        elif name:
            try:
                result = self.ise.exec(
                    family="internal_user",
                    function="update_internal_user_by_name",
                    params=self.new_object,
                    handle_func_exception=False,
                ).response
            except exceptions.ApiError as e:
                if not change_password and "Password can't be set to one of the earlier" in e.message:
                    self.ise.object_modify_result(changed=False, result="Object already present, update was attempted but failed because of password")
                    result = {'_changed_': True}
                elif not change_password and "Password can't be set to one of the earlier" in e.details_str:
                    self.ise.object_modify_result(changed=False, result="Object already present, update was attempted but failed because of password")
                    result = {'_changed_': True}
                else:
                    raise e
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if id:
            result = self.ise.exec(
                family="internal_user",
                function="delete_internal_user_by_id",
                params=self.new_object
            ).response
        elif name:
            result = self.ise.exec(
                family="internal_user",
                function="delete_internal_user_by_name",
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
        obj = InternalUser(self._task.args, ise)

        state = self._task.args.get("state")

        response = None

        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    try:
                        response = obj.update()
                        ise_update_response = response
                        self._result.update(dict(ise_update_response=ise_update_response))
                        if response and response.get('_changed_'):
                            response = prev_obj
                        else:
                            (obj_exists, updated_obj) = obj.exists()
                            response = updated_obj
                            ise.object_updated()
                    except Exception as e:
                        ise.fail_json(
                            msg=(
                                "An error occured when executing operation."
                                " The error was: {error}"
                            ).format(error=e)
                        )
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
