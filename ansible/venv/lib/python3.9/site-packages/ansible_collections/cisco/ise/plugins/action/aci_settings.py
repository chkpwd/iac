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
    state=dict(type="str", default="present", choices=["present"]),
    id=dict(type="str"),
    enableAci=dict(type="bool"),
    ipAddressHostName=dict(type="str"),
    adminName=dict(type="str"),
    adminPassword=dict(type="str"),
    aciipaddress=dict(type="str"),
    aciuserName=dict(type="str"),
    acipassword=dict(type="str"),
    tenantName=dict(type="str"),
    l3RouteNetwork=dict(type="str"),
    suffixToEpg=dict(type="str"),
    suffixToSgt=dict(type="str"),
    allSxpDomain=dict(type="bool"),
    specificSxpDomain=dict(type="bool"),
    specifixSxpDomainList=dict(type="list"),
    enableDataPlane=dict(type="bool"),
    untaggedPacketIepgName=dict(type="str"),
    defaultSgtName=dict(type="str"),
    enableElementsLimit=dict(type="bool"),
    maxNumIepgFromAci=dict(type="int"),
    maxNumSgtToAci=dict(type="int"),
    aci50=dict(type="bool"),
    aci51=dict(type="bool"),
))

required_if = [
    ("state", "present", ["id"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class AciSettings(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            id=params.get("id"),
            enable_aci=params.get("enableAci"),
            ip_address_host_name=params.get("ipAddressHostName"),
            admin_name=params.get("adminName"),
            admin_password=params.get("adminPassword"),
            aciipaddress=params.get("aciipaddress"),
            aciuser_name=params.get("aciuserName"),
            acipassword=params.get("acipassword"),
            tenant_name=params.get("tenantName"),
            l3_route_network=params.get("l3RouteNetwork"),
            suffix_to_epg=params.get("suffixToEpg"),
            suffix_to_sgt=params.get("suffixToSgt"),
            all_sxp_domain=params.get("allSxpDomain"),
            specific_sxp_domain=params.get("specificSxpDomain"),
            specifix_sxp_domain_list=params.get("specifixSxpDomainList"),
            enable_data_plane=params.get("enableDataPlane"),
            untagged_packet_iepg_name=params.get("untaggedPacketIepgName"),
            default_sgt_name=params.get("defaultSgtName"),
            enable_elements_limit=params.get("enableElementsLimit"),
            max_num_iepg_from_aci=params.get("maxNumIepgFromAci"),
            max_num_sgt_to_aci=params.get("maxNumSgtToAci"),
            aci50=params.get("aci50"),
            aci51=params.get("aci51"),
        )

    def get_object_by_name(self, name):
        # NOTICE: Does not have a get by name method or it is in another action
        result = None
        items = self.ise.exec(
            family="aci_settings",
            function="get_aci_settings"
        ).response['AciSettings']
        result = get_dict_result(items, 'name', name)
        return result

    def get_object_by_id(self, id):
        # NOTICE: Does not have a get by id method or it is in another action
        try:
            result = self.ise.exec(
                family="aci_settings",
                function="get_aci_settings",
                handle_func_exception=False,
            ).response['AciSettings']
            # result = get_dict_result(result, 'id', id)
        except Exception as e:
            result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
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
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("id", "id"),
            ("enableAci", "enable_aci"),
            ("ipAddressHostName", "ip_address_host_name"),
            ("adminName", "admin_name"),
            ("adminPassword", "admin_password"),
            ("aciipaddress", "aciipaddress"),
            ("aciuserName", "aciuser_name"),
            ("acipassword", "acipassword"),
            ("tenantName", "tenant_name"),
            ("l3RouteNetwork", "l3_route_network"),
            ("suffixToEpg", "suffix_to_epg"),
            ("suffixToSgt", "suffix_to_sgt"),
            ("allSxpDomain", "all_sxp_domain"),
            ("specificSxpDomain", "specific_sxp_domain"),
            ("specifixSxpDomainList", "specifix_sxp_domain_list"),
            ("enableDataPlane", "enable_data_plane"),
            ("untaggedPacketIepgName", "untagged_packet_iepg_name"),
            ("defaultSgtName", "default_sgt_name"),
            ("enableElementsLimit", "enable_elements_limit"),
            ("maxNumIepgFromAci", "max_num_iepg_from_aci"),
            ("maxNumSgtToAci", "max_num_sgt_to_aci"),
            ("aci50", "aci50"),
            ("aci51", "aci51"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            id_ = self.get_object_by_name(name).get("id")
            self.new_object.update(dict(id=id_))
        result = self.ise.exec(
            family="aci_settings",
            function="update_aci_settings_by_id",
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
        obj = AciSettings(self._task.args, ise)

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
                ise.fail_json("Object does not exists, plugin only has update")

        self._result.update(dict(ise_response=response))
        self._result.update(ise.exit_json())
        return self._result
