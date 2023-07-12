# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The module file for cp_mgmt_threat_rules
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible.plugins.action import ActionBase
from ansible.module_utils.connection import Connection

from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.check_point.mgmt.plugins.module_utils.checkpoint import (
    CheckPointRequest,
    map_params_to_obj,
    sync_show_params_with_add_params,
    remove_unwanted_key,
    contains_show_identifier_param,
)
from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
    AnsibleArgSpecValidator,
)
from ansible_collections.check_point.mgmt.plugins.modules.cp_mgmt_threat_rules import (
    DOCUMENTATION,
)


class ActionModule(ActionBase):
    """action module"""

    def __init__(self, *args, **kwargs):
        super(ActionModule, self).__init__(*args, **kwargs)
        self._result = None
        self.api_call_object = "threat-rule"
        self.module_return = "mgmt_threat_rules"
        self.key_transform = {
            "position": "position",
            "destination_negate": "destination-negate",
            "install_on": "install-on",
            "protected_scope": "protected-scope",
            "protected_scope_negate": "protected-scope-negate",
            "service_negate": "service-negate",
            "source_negate": "source-negate",
            "track_settings": "track-settings",
            "packet_capture": "packet-capture",
            "details_level": "details-level",
            "ignore_warnings": "ignore-warnings",
            "ignore_errors": "ignore-errors",
        }

    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=DOCUMENTATION,
            schema_format="doc",
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            self._result["failed"] = True
            self._result["msg"] = errors

    def search_for_existing_rules(
        self, conn_request, api_call_object, search_payload=None, state=None
    ):
        result = conn_request.post(api_call_object, state, data=search_payload)
        return result

    def search_for_resource_name(self, conn_request, payload):
        search_result = []
        search_payload = utils.remove_empties(payload)
        if not contains_show_identifier_param(search_payload):
            search_result = self.search_for_existing_rules(
                conn_request,
                self.api_call_object_plural_version,
                search_payload,
                "gathered",
            )
        else:
            search_result = self.search_for_existing_rules(
                conn_request, self.api_call_object, search_payload, "gathered"
            )
        search_result = sync_show_params_with_add_params(
            search_result["response"], self.key_transform
        )
        if (
            search_result.get("code")
            and "object_not_found" in search_result.get("code")
            and "not found" in search_result.get("message")
        ):
            search_result = {}
        return search_result

    def delete_module_api_config(self, conn_request, module_config_params):
        config = {}
        before = {}
        after = {}
        changed = False
        result = {}
        payload = utils.remove_empties(module_config_params)
        remove_from_response = ["uid", "read-only", "domain"]
        search_result = self.search_for_resource_name(conn_request, payload)
        if search_result:
            search_result = remove_unwanted_key(
                search_result, remove_from_response
            )
            before = search_result
        result = conn_request.post(
            self.api_call_object, self._task.args["state"], data=payload
        )
        if before:
            config.update({"before": before, "after": after})
        else:
            config.update({"before": before})
        if result.get("changed"):
            changed = True
        return config, changed

    def configure_module_api(self, conn_request, module_config_params):
        config = {}
        before = {}
        after = {}
        changed = False
        result = {}
        # Add to the THIS list for the value which needs to be excluded
        # from HAVE params when compared to WANT param like 'ID' can be
        # part of HAVE param but may not be part of your WANT param
        remove_from_response = ["uid", "read-only", "domain"]
        remove_from_set = []
        payload = utils.remove_empties(module_config_params)
        if payload.get("name"):
            search_payload = {
                "name": payload["name"],
                "layer": payload["layer"],
            }
            search_result = self.search_for_resource_name(
                conn_request, search_payload
            )
            if search_result:
                search_result = remove_unwanted_key(
                    search_result, remove_from_response
                )
                before = search_result
        payload = map_params_to_obj(payload, self.key_transform)
        delete_params = {
            "name": payload["name"],
        }
        result = conn_request.post(
            self.api_call_object,
            self._task.args["state"],
            data=payload,
            remove_keys=remove_from_set,
            delete_params=delete_params,
        )
        if result.get("changed"):
            search_result = sync_show_params_with_add_params(
                result["response"], self.key_transform
            )
            search_result = remove_unwanted_key(
                search_result, remove_from_response
            )
            after = search_result
            changed = True
        config.update({"before": before, "after": after})

        return config, changed

    def run(self, tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._check_argspec()
        if self._result.get("failed"):
            return self._result
        conn = Connection(self._connection.socket_path)
        conn_request = CheckPointRequest(connection=conn, task_vars=task_vars)
        if self._task.args["state"] == "gathered":
            if self._task.args.get("config"):
                self._result["gathered"] = self.search_for_resource_name(
                    conn_request, self._task.args["config"]
                )
            else:
                self._result["gathered"] = self.search_for_resource_name(
                    conn_request, dict()
                )
        elif (
            self._task.args["state"] == "merged"
            or self._task.args["state"] == "replaced"
        ):
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.configure_module_api(
                    conn_request, self._task.args["config"]
                )
        elif self._task.args["state"] == "deleted":
            if self._task.args.get("config"):
                (
                    self._result[self.module_return],
                    self._result["changed"],
                ) = self.delete_module_api_config(
                    conn_request, self._task.args["config"]
                )

        return self._result
