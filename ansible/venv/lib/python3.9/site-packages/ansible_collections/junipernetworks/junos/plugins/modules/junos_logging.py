#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2017, Ansible by Red Hat, inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function


__metaclass__ = type


DOCUMENTATION = """
module: junos_logging
author: Ganesh Nalawade (@ganeshrn)
short_description: Manage logging on network devices
description:
- This module provides declarative management of logging on Juniper JUNOS devices.
version_added: 1.0.0
extends_documentation_fragment:
- junipernetworks.junos.junos
deprecated:
  alternative: junos_logging_global
  why: Updated module released with more functionality.
  removed_at_date: '2023-08-01'
options:
  dest:
    description:
      - Destination of the logs.
    choices:
      - console
      - host
      - file
      - user
    type: str
  name:
    description:
      - If value of C(dest) is I(file) it indicates file-name, for I(user) it indicates
        username and for I(host) indicates the host name to be notified.
    type: str
  facility:
    description:
      - Set logging facility.
    type: str
  level:
    description:
      - Set logging severity levels.
    type: str
  aggregate:
    description:
      - List of logging definitions.
    type: list
    elements: dict
    suboptions:
      dest:
        description:
          - Destination of the logs.
        choices:
          - console
          - host
          - file
          - user
        type: str
      name:
        description:
          - If value of C(dest) is I(file) it indicates file-name, for I(user) it indicates
            username and for I(host) indicates the host name to be notified.
        type: str
      facility:
        description:
          - Set logging facility.
        type: str
      level:
        description:
          - Set logging severity levels.
        type: str
      state:
        description:
          - State of the logging configuration.
        type: str
        choices:
          - present
          - absent
      active:
        description:
          - Specifies whether or not the configuration is active or deactivated
        type: bool
      rotate_frequency:
        description:
          - Rotate log frequency in minutes, this is applicable if value of I(dest) is C(file).
            The acceptable value is in range of 1 to 59. This controls the frequency after
            which log file is rotated.
        type: int
        required: false
      size:
        description:
          - Size of the file in archive, this is applicable if value of I(dest) is C(file).
            The acceptable value is in range from 65536 to 1073741824 bytes.
        type: int
        required: false
      files:
        description:
          - Number of files to be archived, this is applicable if value of I(dest) is C(file).
            The acceptable value is in range from 1 to 1000.
        type: int
        required: false
  state:
    description:
      - State of the logging configuration.
    default: present
    type: str
    choices:
      - present
      - absent
  active:
    description:
      - Specifies whether or not the configuration is active or deactivated
    default: true
    type: bool
  rotate_frequency:
    description:
      - Rotate log frequency in minutes, this is applicable if value of I(dest) is C(file).
        The acceptable value is in range of 1 to 59. This controls the frequency after
        which log file is rotated.
    type: int
    required: false
  size:
    description:
      - Size of the file in archive, this is applicable if value of I(dest) is C(file).
        The acceptable value is in range from 65536 to 1073741824 bytes.
    required: false
    type: int
  files:
    description:
      - Number of files to be archived, this is applicable if value of I(dest) is C(file).
        The acceptable value is in range from 1 to 1000.
    type: int
    required: false
requirements:
- ncclient (>=v0.5.2)
notes:
- This module requires the netconf system service be enabled on the remote device
  being managed.
- Tested against vSRX JUNOS version 15.1X49-D15.4, vqfx-10000 JUNOS Version 15.1X53-D60.4.
- Recommended connection is C(netconf). See L(the Junos OS Platform Options,../network/user_guide/platform_junos.html).
- This module also works with C(local) connections for legacy playbooks.
"""

EXAMPLES = """
- name: configure console logging
  junipernetworks.junos.junos_logging:
    dest: console
    facility: any
    level: critical

- name: remove console logging configuration
  junipernetworks.junos.junos_logging:
    dest: console
    state: absent

- name: configure file logging
  junipernetworks.junos.junos_logging:
    dest: file
    name: test
    facility: pfe
    level: error

- name: configure logging parameter
  junipernetworks.junos.junos_logging:
    files: 30
    size: 65536
    rotate_frequency: 10

- name: Configure file logging using aggregate
  junipernetworks.junos.junos_logging:
    dest: file
    aggregate:
    - name: test-1
      facility: pfe
      level: critical
    - name: test-2
      facility: kernel
      level: emergency
    active: true

- name: Delete file logging using aggregate
  junipernetworks.junos.junos_logging:
    aggregate:
    - {dest: file, name: test-1, facility: pfe, level: critical}
    - {dest: file, name: test-2, facility: kernel, level: emergency}
    state: absent
"""

RETURN = """
diff.prepared:
  description: Configuration difference before and after applying change.
  returned: when configuration is changed and diff option is enabled.
  type: str
  sample: >
          [edit system syslog]
          +    [edit system syslog]
               file interactive-commands { ... }
          +    file test {
          +        pfe critical;
          +    }
"""
import collections

from copy import deepcopy

from ansible.module_utils._text import to_text
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.common.validation import check_required_if
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    remove_default_spec,
)

from ansible_collections.junipernetworks.junos.plugins.module_utils.network.junos.junos import (
    commit_configuration,
    discard_changes,
    load_config,
    locked_config,
    map_obj_to_ele,
    map_params_to_obj,
    to_param_list,
    tostring,
)


USE_PERSISTENT_CONNECTION = True


def validate_files(value, module):
    if value and not 1 <= value <= 1000:
        module.fail_json(msg="files must be between 1 and 1000")


def validate_size(value, module):
    if value and not 65536 <= value <= 1073741824:
        module.fail_json(msg="size must be between 65536 and 1073741824")


def validate_rotate_frequency(value, module):
    if value and not 1 <= value <= 59:
        module.fail_json(msg="rotate_frequency must be between 1 and 59")


def validate_param_values(module, obj, param=None):
    if not param:
        param = module.params
    for key in obj:
        # validate the param value (if validator func exists)
        validator = globals().get("validate_%s" % key)
        if callable(validator):
            validator(param.get(key), module)


def main():
    """main entry point for module execution"""
    element_spec = dict(
        dest=dict(choices=["console", "host", "file", "user"]),
        name=dict(),
        facility=dict(),
        level=dict(),
        rotate_frequency=dict(type="int"),
        size=dict(type="int"),
        files=dict(type="int"),
        state=dict(default="present", choices=["present", "absent"]),
        active=dict(default=True, type="bool"),
    )

    aggregate_spec = deepcopy(element_spec)

    # remove default in aggregate spec, to handle common arguments
    remove_default_spec(aggregate_spec)

    argument_spec = dict(
        aggregate=dict(type="list", elements="dict", options=aggregate_spec),
    )

    argument_spec.update(element_spec)

    required_if = [
        ("dest", "host", ["name", "facility", "level"]),
        ("dest", "file", ["name", "facility", "level"]),
        ("dest", "user", ["name", "facility", "level"]),
        ("dest", "console", ["facility", "level"]),
    ]

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=required_if,
        supports_check_mode=True,
    )

    warnings = list()
    result = {"changed": False}

    if warnings:
        result["warnings"] = warnings

    params = to_param_list(module)

    requests = list()
    for param in params:
        # if key doesn't exist in the item, get it from module.params
        for key in param:
            if param.get(key) is None:
                param[key] = module.params[key]

        try:
            check_required_if(required_if, param)
        except TypeError as exc:
            module.fail_json(to_text(exc))

        item = param.copy()
        dest = item.get("dest")
        if dest == "console" and item.get("name"):
            module.fail_json(
                msg="%s and %s are mutually exclusive" % ("console", "name"),
            )

        top = "system/syslog"
        is_facility_key = False
        field_top = None
        if dest:
            if dest == "console":
                field_top = dest
                is_facility_key = True
            else:
                field_top = dest + "/contents"
                is_facility_key = False

        param_to_xpath_map = collections.OrderedDict()
        param_to_xpath_map.update(
            [
                ("name", {"xpath": "name", "is_key": True, "top": dest}),
                (
                    "facility",
                    {
                        "xpath": "name",
                        "is_key": is_facility_key,
                        "top": field_top,
                    },
                ),
                (
                    "size",
                    {
                        "xpath": "size",
                        "leaf_only": True,
                        "is_key": True,
                        "top": "archive",
                    },
                ),
                (
                    "files",
                    {
                        "xpath": "files",
                        "leaf_only": True,
                        "is_key": True,
                        "top": "archive",
                    },
                ),
                (
                    "rotate_frequency",
                    {"xpath": "log-rotate-frequency", "leaf_only": True},
                ),
            ],
        )

        if item.get("level"):
            param_to_xpath_map["level"] = {
                "xpath": item.get("level"),
                "tag_only": True,
                "top": field_top,
            }

        validate_param_values(module, param_to_xpath_map, param=item)

        want = map_params_to_obj(module, param_to_xpath_map, param=item)
        requests.append(map_obj_to_ele(module, want, top, param=item))

    diff = None
    with locked_config(module):
        for req in requests:
            diff = load_config(module, tostring(req), warnings, action="merge")

        commit = not module.check_mode
        if diff:
            if commit:
                commit_configuration(module)
            else:
                discard_changes(module)
            result["changed"] = True

            if module._diff:
                result["diff"] = {"prepared": diff}

    module.exit_json(**result)


if __name__ == "__main__":
    main()
