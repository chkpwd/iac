# Copyright: (c) 2021, Aubin Bikouo (@abikouo)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
name: turbo_demo
author:
  - Aubin Bikouo (@abikouo)

short_description: A demo for lookup plugins on cloud.common
description:
  - return the parent process of the running process
options:
  playbook_vars:
    description: list of playbook variables to add in the output.
    type: list
    elements: str
"""

EXAMPLES = r"""
"""

RETURN = r"""
"""


import os
import sys
import traceback

from ansible_collections.cloud.common.plugins.plugin_utils.turbo.lookup import (
    TurboLookupBase as LookupBase,
)


def counter():
    counter.i += 1
    return counter.i


# NOTE: workaround to avoid a warning with ansible-doc
if True:  # pylint: disable=using-constant-test
    counter.i = 0


async def execute(terms, variables, playbook_vars):
    result = []
    result.append("running from pid: {pid}".format(pid=os.getpid()))
    if playbook_vars is not None:
        result += [
            variables["vars"].get(x) for x in playbook_vars if x in variables["vars"]
        ]
    if terms:
        result += terms

    for id, stack in list(sys._current_frames().items()):
        for fname, line_id, name, line in traceback.extract_stack(stack):
            if fname == __file__:
                continue

    result.append("turbo_demo_counter: {0}".format(counter()))
    return result


class LookupModule(LookupBase):
    async def _run(self, terms, variables=None, playbook_vars=None):
        result = await execute(terms, variables, playbook_vars)
        return result

    run = _run if not hasattr(LookupBase, "run_on_daemon") else LookupBase.run_on_daemon
