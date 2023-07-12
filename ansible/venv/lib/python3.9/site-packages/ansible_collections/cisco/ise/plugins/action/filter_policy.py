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
import re
try:
    import ipaddress
except ImportError:
    IPADDRESS_INSTALLED = False
else:
    IPADDRESS_INSTALLED = True
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
    subnet=dict(type="str"),
    domains=dict(type="str"),
    sgt=dict(type="str"),
    vn=dict(type="str"),
    id=dict(type="str"),
))

required_if = [
    ("state", "absent", ["id"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class FilterPolicy(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            subnet=params.get("subnet"),
            domains=params.get("domains"),
            sgt=params.get("sgt"),
            vn=params.get("vn"),
            id=params.get("id"),
        )

    def is_same_subnet(self, new, current):
        if IPADDRESS_INSTALLED:
            new_net = None
            current_net = None
            try:
                new_net = ipaddress.ip_network(new, strict=False)
            except ValueError:
                new_net = None
            try:
                current_net = ipaddress.ip_network(current, strict=False)
            except ValueError:
                current_net = None
            if new_net and current_net:
                conflict = current_net.overlaps(new_net) or new_net.overlaps(current_net)
                # conflict = current_net.subnet_of(new_net) or new_net.subnet_of(current_net)
                # They are the mostly the same, both have overlapping net
                return conflict
            elif new_net is None and current_net is None:
                return True
            else:
                return False
        else:
            if new and current:
                return new == current
            else:
                return not current and not new

    def get_sgt_by_name(self, name):
        if not name:
            return None
        try:
            gen_items_responses = self.ise.exec(
                family="filter_policy",
                function="get_filter_policy_generator"
            )
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

    def get_sgt_by_id(self, id):
        if not id:
            return None
        try:
            result = self.ise.exec(
                family="sgt",
                function="get_security_group_by_id",
                params={"id": id},
                handle_func_exception=False,
            ).response['Sgt']
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

    def is_same_sgt(self, new, current):
        # Values can be id or name
        def clean_excess(name):
            if name:
                return re.sub(r"\s*\(.*\)$", "", name)
            else:
                return name
        has_new = self.get_sgt_by_id(new) or self.get_sgt_by_name(clean_excess(new))
        has_current = self.get_sgt_by_id(current) or self.get_sgt_by_name(clean_excess(current))
        if has_new and has_current:
            return has_new.get("id") == has_current.get("id")
        else:
            return not has_current and not has_new

    def is_same_vn(self, new, current):
        if new and current:
            return new == current
        else:
            return not current and not new

    def get_object_by_name(self, name, new_subnet, new_sgt, new_vn):
        # NOTICE: Does not have a get by name method or it is in another action
        result = None
        gen_items_responses = self.ise.exec(
            family="filter_policy",
            function="get_filter_policy_generator"
        )
        try:
            for items_response in gen_items_responses:
                items = items_response.response['SearchResult']['resources']
                for item in items:
                    current = self.get_object_by_id(item.get('id'))
                    if current:
                        has_same_subnet = self.is_same_subnet(new_subnet, current.get('subnet'))
                        has_same_sgt = self.is_same_sgt(new_sgt, current.get('sgt'))
                        has_same_vn = self.is_same_vn(new_vn, current.get('vn'))
                    if has_same_subnet and has_same_sgt and has_same_vn:
                        result = dict(current)
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
                family="filter_policy",
                function="get_filter_policy_by_id",
                handle_func_exception=False,
                params={"id": id}
            ).response['ERSFilterPolicy']
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
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get("id")
        id_exists = o_id and self.get_object_by_id(o_id)
        if id_exists:
            prev_obj = self.get_object_by_id(o_id)
        if not id_exists:
            name = self.new_object.get("name")
            subnet = self.new_object.get("subnet")
            sgt = self.new_object.get("sgt")
            vn = self.new_object.get("vn")
            prev_obj = self.get_object_by_name(name, subnet, sgt, vn)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
            if name_exists:
                id_ = prev_obj.get("id")
                self.new_object.update(dict(id=id_))
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("subnet", "subnet"),
            ("domains", "domains"),
            ("sgt", "sgt"),
            ("vn", "vn"),
            ("id", "id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def create(self):
        result = self.ise.exec(
            family="filter_policy",
            function="create_filter_policy",
            params=self.new_object,
        ).response
        return result

    def update(self):
        result = self.ise.exec(
            family="filter_policy",
            function="update_filter_policy_by_id",
            params=self.new_object
        ).response
        return result

    def delete(self):
        result = self.ise.exec(
            family="filter_policy",
            function="delete_filter_policy_by_id",
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
        obj = FilterPolicy(self._task.args, ise)

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
