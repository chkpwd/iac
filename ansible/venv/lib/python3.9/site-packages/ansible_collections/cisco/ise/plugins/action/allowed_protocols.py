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
    eapTls=dict(type="dict"),
    peap=dict(type="dict"),
    eapFast=dict(type="dict"),
    eapTtls=dict(type="dict"),
    teap=dict(type="dict"),
    processHostLookup=dict(type="bool"),
    allowPapAscii=dict(type="bool"),
    allowChap=dict(type="bool"),
    allowMsChapV1=dict(type="bool"),
    allowMsChapV2=dict(type="bool"),
    allowEapMd5=dict(type="bool"),
    allowLeap=dict(type="bool"),
    allowEapTls=dict(type="bool"),
    allowEapTtls=dict(type="bool"),
    allowEapFast=dict(type="bool"),
    allowPeap=dict(type="bool"),
    allowTeap=dict(type="bool"),
    allowPreferredEapProtocol=dict(type="bool"),
    preferredEapProtocol=dict(type="str"),
    eapTlsLBit=dict(type="bool"),
    allowWeakCiphersForEap=dict(type="bool"),
    requireMessageAuth=dict(type="bool"),
    id=dict(type="str"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class AllowedProtocols(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            name=params.get("name"),
            description=params.get("description"),
            eap_tls=params.get("eapTls"),
            peap=params.get("peap"),
            eap_fast=params.get("eapFast"),
            eap_ttls=params.get("eapTtls"),
            teap=params.get("teap"),
            process_host_lookup=params.get("processHostLookup"),
            allow_pap_ascii=params.get("allowPapAscii"),
            allow_chap=params.get("allowChap"),
            allow_ms_chap_v1=params.get("allowMsChapV1"),
            allow_ms_chap_v2=params.get("allowMsChapV2"),
            allow_eap_md5=params.get("allowEapMd5"),
            allow_leap=params.get("allowLeap"),
            allow_eap_tls=params.get("allowEapTls"),
            allow_eap_ttls=params.get("allowEapTtls"),
            allow_eap_fast=params.get("allowEapFast"),
            allow_peap=params.get("allowPeap"),
            allow_teap=params.get("allowTeap"),
            allow_preferred_eap_protocol=params.get("allowPreferredEapProtocol"),
            preferred_eap_protocol=params.get("preferredEapProtocol"),
            eap_tls_l_bit=params.get("eapTlsLBit"),
            allow_weak_ciphers_for_eap=params.get("allowWeakCiphersForEap"),
            require_message_auth=params.get("requireMessageAuth"),
            id=params.get("id"),
        )

    def get_object_by_name(self, name):
        try:
            result = self.ise.exec(
                family="allowed_protocols",
                function="get_allowed_protocol_by_name",
                params={"name": name},
                handle_func_exception=False,
            ).response['AllowedProtocols']
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
                family="allowed_protocols",
                function="get_allowed_protocol_by_id",
                handle_func_exception=False,
                params={"id": id}
            ).response['AllowedProtocols']
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
            ("eapTls", "eap_tls"),
            ("peap", "peap"),
            ("eapFast", "eap_fast"),
            ("eapTtls", "eap_ttls"),
            ("teap", "teap"),
            ("processHostLookup", "process_host_lookup"),
            ("allowPapAscii", "allow_pap_ascii"),
            ("allowChap", "allow_chap"),
            ("allowMsChapV1", "allow_ms_chap_v1"),
            ("allowMsChapV2", "allow_ms_chap_v2"),
            ("allowEapMd5", "allow_eap_md5"),
            ("allowLeap", "allow_leap"),
            ("allowEapTls", "allow_eap_tls"),
            ("allowEapTtls", "allow_eap_ttls"),
            ("allowEapFast", "allow_eap_fast"),
            ("allowPeap", "allow_peap"),
            ("allowTeap", "allow_teap"),
            ("allowPreferredEapProtocol", "allow_preferred_eap_protocol"),
            ("preferredEapProtocol", "preferred_eap_protocol"),
            ("eapTlsLBit", "eap_tls_l_bit"),
            ("allowWeakCiphersForEap", "allow_weak_ciphers_for_eap"),
            ("requireMessageAuth", "require_message_auth"),
            ("id", "id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="allowed_protocols",
            function="create_allowed_protocol",
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
            family="allowed_protocols",
            function="update_allowed_protocol_by_id",
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
            family="allowed_protocols",
            function="delete_allowed_protocol_by_id",
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
        obj = AllowedProtocols(self._task.args, ise)

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
