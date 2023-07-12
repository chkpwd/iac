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
    id=dict(type="str"),
    name=dict(type="str"),
    description=dict(type="str"),
    advancedAttributes=dict(type="list"),
    accessType=dict(type="str"),
    authzProfileType=dict(type="str"),
    vlan=dict(type="dict"),
    reauth=dict(type="dict"),
    airespaceACL=dict(type="str"),
    airespaceIPv6ACL=dict(type="str"),
    webRedirection=dict(type="dict"),
    acl=dict(type="str"),
    trackMovement=dict(type="bool"),
    agentlessPosture=dict(type="bool"),
    serviceTemplate=dict(type="bool"),
    easywiredSessionCandidate=dict(type="bool"),
    daclName=dict(type="str"),
    voiceDomainPermission=dict(type="bool"),
    neat=dict(type="bool"),
    webAuth=dict(type="bool"),
    autoSmartPort=dict(type="str"),
    interfaceTemplate=dict(type="str"),
    ipv6ACLFilter=dict(type="str"),
    avcProfile=dict(type="str"),
    macSecPolicy=dict(type="str"),
    asaVpn=dict(type="str"),
    profileName=dict(type="str"),
    ipv6DaclName=dict(type="str"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class AuthorizationProfile(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            id=params.get("id"),
            name=params.get("name"),
            description=params.get("description"),
            advanced_attributes=params.get("advancedAttributes"),
            access_type=params.get("accessType"),
            authz_profile_type=params.get("authzProfileType"),
            vlan=params.get("vlan"),
            reauth=params.get("reauth"),
            airespace_acl=params.get("airespaceACL"),
            airespace_ipv6_acl=params.get("airespaceIPv6ACL"),
            web_redirection=params.get("webRedirection"),
            acl=params.get("acl"),
            track_movement=params.get("trackMovement"),
            agentless_posture=params.get("agentlessPosture"),
            service_template=params.get("serviceTemplate"),
            easywired_session_candidate=params.get("easywiredSessionCandidate"),
            dacl_name=params.get("daclName"),
            voice_domain_permission=params.get("voiceDomainPermission"),
            neat=params.get("neat"),
            web_auth=params.get("webAuth"),
            auto_smart_port=params.get("autoSmartPort"),
            interface_template=params.get("interfaceTemplate"),
            ipv6_acl_filter=params.get("ipv6ACLFilter"),
            avc_profile=params.get("avcProfile"),
            mac_sec_policy=params.get("macSecPolicy"),
            asa_vpn=params.get("asaVpn"),
            profile_name=params.get("profileName"),
            ipv6_dacl_name=params.get("ipv6DaclName"),
        )

    def get_object_by_name(self, name):
        try:
            result = self.ise.exec(
                family="authorization_profile",
                function="get_authorization_profile_by_name",
                params={"name": name},
                handle_func_exception=False,
            ).response['AuthorizationProfile']
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
                family="authorization_profile",
                function="get_authorization_profile_by_id",
                handle_func_exception=False,
                params={"id": id}
            ).response['AuthorizationProfile']
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
            ("id", "id"),
            ("name", "name"),
            ("description", "description"),
            ("advancedAttributes", "advanced_attributes"),
            ("accessType", "access_type"),
            ("authzProfileType", "authz_profile_type"),
            ("vlan", "vlan"),
            ("reauth", "reauth"),
            ("airespaceACL", "airespace_acl"),
            ("airespaceIPv6ACL", "airespace_ipv6_acl"),
            ("webRedirection", "web_redirection"),
            ("acl", "acl"),
            ("trackMovement", "track_movement"),
            ("agentlessPosture", "agentless_posture"),
            ("serviceTemplate", "service_template"),
            ("easywiredSessionCandidate", "easywired_session_candidate"),
            ("daclName", "dacl_name"),
            ("voiceDomainPermission", "voice_domain_permission"),
            ("neat", "neat"),
            ("webAuth", "web_auth"),
            ("autoSmartPort", "auto_smart_port"),
            ("interfaceTemplate", "interface_template"),
            ("ipv6ACLFilter", "ipv6_acl_filter"),
            ("avcProfile", "avc_profile"),
            ("macSecPolicy", "mac_sec_policy"),
            ("asaVpn", "asa_vpn"),
            ("profileName", "profile_name"),
            ("ipv6DaclName", "ipv6_dacl_name"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="authorization_profile",
            function="create_authorization_profile",
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
            family="authorization_profile",
            function="update_authorization_profile_by_id",
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
            family="authorization_profile",
            function="delete_authorization_profile_by_id",
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
        obj = AuthorizationProfile(self._task.args, ise)

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
