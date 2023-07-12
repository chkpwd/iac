# -*- coding: utf-8 -*-
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible.module_utils.six import text_type
from ansible.plugins.action import ActionBase
from ansible.utils.vars import merge_hash

from ..module_utils import bonsai, errors


def validate(name, args, required, typ):
    """
    Make sure that required values are not None and that if the value is
    present, it is of the correct type.
    """
    value = args.get(name)
    if required and value is None:
        raise errors.Error("{0} is required argument".format(name))
    if value is not None and not isinstance(value, typ):
        raise errors.Error("{0} should be {1}".format(name, typ))


class ActionModule(ActionBase):

    _VALID_ARGS = frozenset((
        "auth", "name", "version", "namespace", "rename", "labels",
        "annotations", "on_remote",
    ))

    def run(self, _tmp=None, task_vars=None):
        self._supports_check_mode = True
        self._supports_async = True

        result = super(ActionModule, self).run(task_vars=task_vars)

        wrap_async = (
            self._task.async_val and not self._connection.has_native_async
        )

        try:
            self.validate_arguments(self._task.args)
            asset = self.download_asset_definition(
                self._task.args.get("on_remote", False),
                self._task.args["name"],
                self._task.args["version"],
                task_vars,
            )
            asset_args = self.build_asset_args(self._task.args, asset)
            return merge_hash(
                result,
                self._execute_module(
                    module_name="sensu.sensu_go.asset", module_args=asset_args,
                    task_vars=task_vars, wrap_async=wrap_async,
                ),
            )
        except errors.Error as e:
            return dict(result, failed=True, msg=str(e))
        finally:
            if not wrap_async:
                self._remove_tmp_path(self._connection._shell.tmpdir)

    @staticmethod
    def validate_arguments(args):
        # We only validate arguments that we use. We let the asset module
        # validate the rest (like auth data).

        # Next three string validations might seem strange at first, but there
        # is a reason for this strangenes. On python 2, we should consider
        # string to be instance of str or unicode. On python 3, strings are
        # always instances of str. In order to avoid having a separate
        # validate calls for python 2 and python 3, we always pass a pair of
        # types that just happen to be the same on python 3.
        validate("name", args, required=True, typ=(str, text_type))
        validate("version", args, required=True, typ=(str, text_type))
        validate("rename", args, required=False, typ=(str, text_type))
        validate("labels", args, required=False, typ=dict)
        validate("annotations", args, required=False, typ=dict)
        validate("on_remote", args, required=False, typ=bool)

    def download_asset_definition(self, on_remote, name, version, task_vars):
        if not on_remote:
            return bonsai.get_asset_parameters(name, version)

        args = dict(name=name, version=version)
        result = self._execute_module(
            module_name="sensu.sensu_go.bonsai_asset", module_args=args,
            task_vars=task_vars, wrap_async=False,
        )
        if result.get("failed", False):
            raise errors.Error(result["msg"])

        return result["asset"]

    @staticmethod
    def build_asset_args(args, bonsai_args):
        asset_args = dict(
            name=args.get("rename", args["name"]),
            state="present",
            builds=bonsai_args["builds"],
        )

        if "auth" in args:
            asset_args["auth"] = args["auth"]

        if "namespace" in args:
            asset_args["namespace"] = args["namespace"]

        # Only add optional parameter if it is present in at least one source.
        for meta in ("labels", "annotations"):
            if bonsai_args[meta] or args.get(meta):
                asset_args[meta] = merge_hash(
                    bonsai_args[meta] or {}, args.get(meta, {}),
                )

        return asset_args
