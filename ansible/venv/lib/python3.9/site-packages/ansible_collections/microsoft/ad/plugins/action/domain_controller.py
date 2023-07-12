# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import typing as t

from ..plugin_utils._module_with_reboot import ActionModuleWithReboot


class ActionModule(ActionModuleWithReboot):
    def __init__(self, *args: t.Any, **kwargs: t.Any) -> None:
        super().__init__(*args, **kwargs)
        self._ran_once = False

    def _ad_should_rerun(self, result: t.Dict[str, t.Any]) -> bool:
        ran_once = self._ran_once
        self._ran_once = True

        if ran_once or not result.get("_do_action_reboot", False):
            return False

        if self._task.check_mode:
            # Assume that on a rerun it will not have failed and that it
            # ran successfull.
            result["failed"] = False
            result.pop("msg", None)
            return False

        else:
            return True

    def _ad_process_result(self, result: t.Dict[str, t.Any]) -> t.Dict[str, t.Any]:
        result.pop("_do_action_reboot", None)

        return result
