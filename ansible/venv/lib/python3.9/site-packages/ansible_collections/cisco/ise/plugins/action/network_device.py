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
    name=dict(type="str"),
    description=dict(type="str"),
    authenticationSettings=dict(type="dict"),
    snmpsettings=dict(type="dict"),
    trustsecsettings=dict(type="dict"),
    tacacsSettings=dict(type="dict"),
    profileName=dict(type="str"),
    coaPort=dict(type="int"),
    dtlsDnsName=dict(type="str"),
    modelName=dict(type="str"),
    softwareVersion=dict(type="str"),
    NetworkDeviceIPList=dict(type="list"),
    NetworkDeviceGroupList=dict(type="list"),
    id=dict(type="str"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworkDevice(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            name=params.get("name"),
            description=params.get("description"),
            authentication_settings=params.get("authenticationSettings"),
            snmpsettings=params.get("snmpsettings"),
            trustsecsettings=params.get("trustsecsettings"),
            tacacs_settings=params.get("tacacsSettings"),
            profile_name=params.get("profileName"),
            coa_port=params.get("coaPort"),
            dtls_dns_name=params.get("dtlsDnsName"),
            model_name=params.get("modelName"),
            software_version=params.get("softwareVersion"),
            network_device_iplist=params.get("NetworkDeviceIPList"),
            network_device_group_list=params.get("NetworkDeviceGroupList"),
            id=params.get("id"),
        )

    def get_object_by_name(self, name):
        try:
            result = self.ise.exec(
                family="network_device",
                function="get_network_device_by_name",
                params={"name": name},
                handle_func_exception=False,
            ).response['NetworkDevice']
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
                family="network_device",
                function="get_network_device_by_id",
                handle_func_exception=False,
                params={"id": id}
            ).response['NetworkDevice']
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
            ("name", "name"),
            ("description", "description"),
            ("authenticationSettings", "authentication_settings"),
            ("snmpsettings", "snmpsettings"),
            ("trustsecsettings", "trustsecsettings"),
            ("tacacsSettings", "tacacs_settings"),
            ("profileName", "profile_name"),
            ("coaPort", "coa_port"),
            ("dtlsDnsName", "dtls_dns_name"),
            ("modelName", "model_name"),
            ("softwareVersion", "software_version"),
            ("NetworkDeviceIPList", "network_device_iplist"),
            ("NetworkDeviceGroupList", "network_device_group_list"),
            ("id", "id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="network_device",
            function="create_network_device",
            params=self.new_object,
        ).response
        return result

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if id:
            result = self.ise.exec(
                family="network_device",
                function="update_network_device_by_id",
                params=self.new_object
            ).response
        elif name:
            result = self.ise.exec(
                family="network_device",
                function="update_network_device_by_name",
                params=self.new_object
            ).response
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if id:
            result = self.ise.exec(
                family="network_device",
                function="delete_network_device_by_id",
                params=self.new_object
            ).response
        elif name:
            result = self.ise.exec(
                family="network_device",
                function="delete_network_device_by_name",
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
        obj = NetworkDevice(self._task.args, ise)

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
