from __future__ import (absolute_import, division, print_function)
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
from urllib.parse import quote
import time
from ansible_collections.cisco.ise.plugins.plugin_utils.personas_utils import Node
from ansible_collections.cisco.ise.plugins.plugin_utils.ise import (
    ise_compare_equality,
)

argument_spec = dict(
    ip=dict(type="str", required=True),
    username=dict(type="str", required=True),
    password=dict(type="str", required=True),
    hostname=dict(type="str", required=True),
    roles=dict(type="list", required=True),
    services=dict(type="list", required=True),
    ise_verify=dict(type="bool", default=True),
    ise_version=dict(type="str", default="3.0.0"),
    ise_wait_on_rate_limit=dict(type="bool", default=True),  # TODO: verify what the true default value should be
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class NodeDeployment(object):
    def requires_update(self, current_obj, requested_obj):
        obj_params = [
            ("roles", "roles"),
            ("services", "services"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)


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
        obj = NodeDeployment()
        request_obj = dict(ip=self._task.args.get("ip"),
                           username=self._task.args.get("username"),
                           password=self._task.args.get("password"),
                           hostname=self._task.args.get("hostname"),
                           roles=self._task.args.get("roles"),
                           services=self._task.args.get("services"),
                           )
        node = Node(request_obj)
        prev_obj = False
        result = dict(changed=False, result="")
        response = None
        if not node.app_server_is_running():
            raise AnsibleActionFail("Couldn't connect, the node might be still initializing, try again in a few minutes. Error received: 502")
        try:
            prev_obj = node.get_roles_services()
        except Exception as e:
            AnsibleActionFail(e)
        if prev_obj:
            if obj.requires_update(prev_obj, request_obj):
                try:
                    node.update_roles_services()
                    response = node.get_roles_services()
                    result["changed"] = True
                    result["result"] = "Object updated"
                except Exception as e:
                    raise AnsibleActionFail("The node might be still initializing. Error received: {e}".format(e=e))
            else:
                response = prev_obj
                result["result"] = "Object already present"
        self._result.update(dict(ise_response=response))
        self._result.update(result)
        return self._result
