#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_pgsched
short_description: Manage protection groups replication schedules on Pure Storage FlashArrays
version_added: '1.0.0'
description:
- Modify or delete protection groups replication schedules on Pure Storage FlashArrays.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  name:
    description:
    - The name of the protection group.
    type: str
    required: true
  state:
    description:
    - Define whether to set or delete the protection group schedule.
    type: str
    default: present
    choices: [ absent, present ]
  schedule:
    description:
    - Which schedule to change.
    type: str
    choices: ['replication', 'snapshot']
    required: true
  enabled:
    description:
    - Enable the schedule being configured.
    type: bool
    default: true
  replicate_at:
    description:
    - Specifies the preferred time as HH:MM:SS, using 24-hour clock, at which to generate snapshots.
    type: int
  blackout_start:
    description:
    - Specifies the time at which to suspend replication.
    - Provide a time in 12-hour AM/PM format, eg. 11AM
    type: str
  blackout_end:
    description:
    - Specifies the time at which to restart replication.
    - Provide a time in 12-hour AM/PM format, eg. 5PM
    type: str
  replicate_frequency:
    description:
    - Specifies the replication frequency in seconds.
    - Range 900 - 34560000 (FA-405, //M10, //X10i and Cloud Block Store).
    - Range 300 - 34560000 (all other arrays).
    type: int
  snap_at:
    description:
    - Specifies the preferred time as HH:MM:SS, using 24-hour clock, at which to generate snapshots.
    - Only valid if I(snap_frequency) is an exact multiple of 86400, ie 1 day.
    type: int
  snap_frequency:
    description:
    - Specifies the snapshot frequency in seconds.
    - Range available 300 - 34560000.
    type: int
  days:
    description:
    - Specifies the number of days to keep the I(per_day) snapshots beyond the
      I(all_for) period before they are eradicated
    - Max retention period is 4000 days
    type: int
  all_for:
    description:
    - Specifies the length of time, in seconds, to keep the snapshots on the
      source array before they are eradicated.
    - Range available 1 - 34560000.
    type: int
  per_day:
    description:
    - Specifies the number of I(per_day) snapshots to keep beyond the I(all_for) period.
    - Maximum number is 1440
    type: int
  target_all_for:
    description:
    - Specifies the length of time, in seconds, to keep the replicated snapshots on the targets.
    - Range is 1 - 34560000 seconds.
    type: int
  target_per_day:
    description:
    - Specifies the number of I(per_day) replicated snapshots to keep beyond the I(target_all_for) period.
    - Maximum number is 1440
    type: int
  target_days:
    description:
    - Specifies the number of days to keep the I(target_per_day) replicated snapshots
      beyond the I(target_all_for) period before they are eradicated.
    - Max retention period is 4000 days
    type: int
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Update protection group snapshot schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: snapshot
    enabled: true
    snap_frequency: 86400
    snap_at: 15:30:00
    per_day: 5
    all_for: 5
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Update protection group replication schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: replication
    enabled: true
    replicate_frequency: 86400
    replicate_at: 15:30:00
    target_per_day: 5
    target_all_for: 5
    blackout_start: 2AM
    blackout_end: 5AM
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete protection group snapshot schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: snapshot
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Delete protection group replication schedule
  purestorage.flasharray.purefa_pgsched:
    name: foo
    schedule: replication
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_system,
    purefa_argument_spec,
)


def get_pending_pgroup(module, array):
    """Get Protection Group"""
    pgroup = None
    if ":" in module.params["name"]:
        for pgrp in array.list_pgroups(pending=True, on="*"):
            if pgrp["name"] == module.params["name"] and pgrp["time_remaining"]:
                pgroup = pgrp
                break
    else:
        for pgrp in array.list_pgroups(pending=True):
            if pgrp["name"] == module.params["name"] and pgrp["time_remaining"]:
                pgroup = pgrp
                break

    return pgroup


def get_pgroup(module, array):
    """Get Protection Group"""
    pgroup = None
    if ":" in module.params["name"]:
        if "::" not in module.params["name"]:
            for pgrp in array.list_pgroups(on="*"):
                if pgrp["name"] == module.params["name"]:
                    pgroup = pgrp
                    break
        else:
            for pgrp in array.list_pgroups():
                if pgrp["name"] == module.params["name"]:
                    pgroup = pgrp
                    break
    else:
        for pgrp in array.list_pgroups():
            if pgrp["name"] == module.params["name"]:
                pgroup = pgrp
                break

    return pgroup


def _convert_to_minutes(hour):
    if hour[-2:] == "AM" and hour[:2] == "12":
        return 0
    elif hour[-2:] == "AM":
        return int(hour[:-2]) * 3600
    elif hour[-2:] == "PM" and hour[:2] == "12":
        return 43200
    return (int(hour[:-2]) + 12) * 3600


def update_schedule(module, array):
    """Update Protection Group Schedule"""
    changed = False
    try:
        schedule = array.get_pgroup(module.params["name"], schedule=True)
        retention = array.get_pgroup(module.params["name"], retention=True)
        if not schedule["replicate_blackout"]:
            schedule["replicate_blackout"] = [{"start": 0, "end": 0}]
    except Exception:
        module.fail_json(
            msg="Failed to get current schedule for pgroup {0}.".format(
                module.params["name"]
            )
        )
    current_repl = {
        "replicate_frequency": schedule["replicate_frequency"],
        "replicate_enabled": schedule["replicate_enabled"],
        "target_days": retention["target_days"],
        "replicate_at": schedule["replicate_at"],
        "target_per_day": retention["target_per_day"],
        "target_all_for": retention["target_all_for"],
        "blackout_start": schedule["replicate_blackout"][0]["start"],
        "blackout_end": schedule["replicate_blackout"][0]["end"],
    }
    current_snap = {
        "days": retention["days"],
        "snap_frequency": schedule["snap_frequency"],
        "snap_enabled": schedule["snap_enabled"],
        "snap_at": schedule["snap_at"],
        "per_day": retention["per_day"],
        "all_for": retention["all_for"],
    }
    if module.params["schedule"] == "snapshot":
        if not module.params["snap_frequency"]:
            snap_frequency = current_snap["snap_frequency"]
        else:
            if not 300 <= module.params["snap_frequency"] <= 34560000:
                module.fail_json(
                    msg="Snap Frequency support is out of range (300 to 34560000)"
                )
            else:
                snap_frequency = module.params["snap_frequency"]

        if not module.params["snap_at"]:
            snap_at = current_snap["snap_at"]
        else:
            snap_at = module.params["snap_at"]

        if not module.params["days"]:
            if isinstance(module.params["days"], int):
                days = module.params["days"]
            else:
                days = current_snap["days"]
        else:
            if module.params["days"] > 4000:
                module.fail_json(msg="Maximum value for days is 4000")
            else:
                days = module.params["days"]

        if module.params["per_day"] is None:
            per_day = current_snap["per_day"]
        else:
            if module.params["per_day"] > 1440:
                module.fail_json(msg="Maximum value for per_day is 1440")
            else:
                per_day = module.params["per_day"]

        if not module.params["all_for"]:
            all_for = current_snap["all_for"]
        else:
            if module.params["all_for"] > 34560000:
                module.fail_json(msg="Maximum all_for value is 34560000")
            else:
                all_for = module.params["all_for"]
        new_snap = {
            "days": days,
            "snap_frequency": snap_frequency,
            "snap_enabled": module.params["enabled"],
            "snap_at": snap_at,
            "per_day": per_day,
            "all_for": all_for,
        }
        if current_snap != new_snap:
            changed = True
            if not module.check_mode:
                try:
                    array.set_pgroup(
                        module.params["name"], snap_enabled=module.params["enabled"]
                    )
                    array.set_pgroup(
                        module.params["name"],
                        snap_frequency=snap_frequency,
                        snap_at=snap_at,
                    )
                    array.set_pgroup(
                        module.params["name"],
                        days=days,
                        per_day=per_day,
                        all_for=all_for,
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to change snapshot schedule for pgroup {0}.".format(
                            module.params["name"]
                        )
                    )
    else:
        if not module.params["replicate_frequency"]:
            replicate_frequency = current_repl["replicate_frequency"]
        else:
            model = array.get(controllers=True)[0]["model"]
            if "405" in model or "10" in model or "CBS" in model:
                if not 900 <= module.params["replicate_frequency"] <= 34560000:
                    module.fail_json(
                        msg="Replication Frequency support is out of range (900 to 34560000)"
                    )
                else:
                    replicate_frequency = module.params["replicate_frequency"]
            else:
                if not 300 <= module.params["replicate_frequency"] <= 34560000:
                    module.fail_json(
                        msg="Replication Frequency support is out of range (300 to 34560000)"
                    )
                else:
                    replicate_frequency = module.params["replicate_frequency"]

        if not module.params["replicate_at"]:
            replicate_at = current_repl["replicate_at"]
        else:
            replicate_at = module.params["replicate_at"]

        if not module.params["target_days"]:
            if isinstance(module.params["target_days"], int):
                target_days = module.params["target_days"]
            else:
                target_days = current_repl["target_days"]
        else:
            if module.params["target_days"] > 4000:
                module.fail_json(msg="Maximum value for target_days is 4000")
            else:
                target_days = module.params["target_days"]

        if not module.params["target_per_day"]:
            if isinstance(module.params["target_per_day"], int):
                target_per_day = module.params["target_per_day"]
            else:
                target_per_day = current_repl["target_per_day"]
        else:
            if module.params["target_per_day"] > 1440:
                module.fail_json(msg="Maximum value for target_per_day is 1440")
            else:
                target_per_day = module.params["target_per_day"]

        if not module.params["target_all_for"]:
            target_all_for = current_repl["target_all_for"]
        else:
            if module.params["target_all_for"] > 34560000:
                module.fail_json(msg="Maximum target_all_for value is 34560000")
            else:
                target_all_for = module.params["target_all_for"]
        if not module.params["blackout_end"]:
            blackout_end = current_repl["blackout_start"]
        else:
            blackout_end = _convert_to_minutes(module.params["blackout_end"])
        if not module.params["blackout_start"]:
            blackout_start = current_repl["blackout_start"]
        else:
            blackout_start = _convert_to_minutes(module.params["blackout_start"])

        new_repl = {
            "replicate_frequency": replicate_frequency,
            "replicate_enabled": module.params["enabled"],
            "target_days": target_days,
            "replicate_at": replicate_at,
            "target_per_day": target_per_day,
            "target_all_for": target_all_for,
            "blackout_start": blackout_start,
            "blackout_end": blackout_end,
        }
        if current_repl != new_repl:
            changed = True
            if not module.check_mode:
                blackout = {"start": blackout_start, "end": blackout_end}
                try:
                    array.set_pgroup(
                        module.params["name"],
                        replicate_enabled=module.params["enabled"],
                    )
                    array.set_pgroup(
                        module.params["name"],
                        replicate_frequency=replicate_frequency,
                        replicate_at=replicate_at,
                    )
                    if blackout_start == 0:
                        array.set_pgroup(module.params["name"], replicate_blackout=None)
                    else:
                        array.set_pgroup(
                            module.params["name"], replicate_blackout=blackout
                        )
                    array.set_pgroup(
                        module.params["name"],
                        target_days=target_days,
                        target_per_day=target_per_day,
                        target_all_for=target_all_for,
                    )
                except Exception:
                    module.fail_json(
                        msg="Failed to change replication schedule for pgroup {0}.".format(
                            module.params["name"]
                        )
                    )

    module.exit_json(changed=changed)


def delete_schedule(module, array):
    """Delete, ie. disable, Protection Group Schedules"""
    changed = False
    try:
        current_state = array.get_pgroup(module.params["name"], schedule=True)
        if module.params["schedule"] == "replication":
            if current_state["replicate_enabled"]:
                changed = True
                if not module.check_mode:
                    array.set_pgroup(module.params["name"], replicate_enabled=False)
                    array.set_pgroup(
                        module.params["name"],
                        target_days=0,
                        target_per_day=0,
                        target_all_for=1,
                    )
                    array.set_pgroup(
                        module.params["name"],
                        replicate_frequency=14400,
                        replicate_blackout=None,
                    )
        else:
            if current_state["snap_enabled"]:
                changed = True
                if not module.check_mode:
                    array.set_pgroup(module.params["name"], snap_enabled=False)
                    array.set_pgroup(
                        module.params["name"], days=0, per_day=0, all_for=1
                    )
                    array.set_pgroup(module.params["name"], snap_frequency=300)
    except Exception:
        module.fail_json(
            msg="Deleting pgroup {0} {1} schedule failed.".format(
                module.params["name"], module.params["schedule"]
            )
        )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            name=dict(type="str", required=True),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            schedule=dict(
                type="str", required=True, choices=["replication", "snapshot"]
            ),
            blackout_start=dict(type="str"),
            blackout_end=dict(type="str"),
            snap_at=dict(type="int"),
            replicate_at=dict(type="int"),
            replicate_frequency=dict(type="int"),
            snap_frequency=dict(type="int"),
            all_for=dict(type="int"),
            days=dict(type="int"),
            per_day=dict(type="int"),
            target_all_for=dict(type="int"),
            target_per_day=dict(type="int"),
            target_days=dict(type="int"),
            enabled=dict(type="bool", default=True),
        )
    )

    required_together = [["blackout_start", "blackout_end"]]

    module = AnsibleModule(
        argument_spec, required_together=required_together, supports_check_mode=True
    )

    state = module.params["state"]
    array = get_system(module)

    pgroup = get_pgroup(module, array)
    if module.params["snap_at"] and module.params["snap_frequency"]:
        if not module.params["snap_frequency"] % 86400 == 0:
            module.fail_json(
                msg="snap_at not valid unless snapshot frequency is measured in days, ie. a multiple of 86400"
            )
    if pgroup and state == "present":
        update_schedule(module, array)
    elif pgroup and state == "absent":
        delete_schedule(module, array)
    elif pgroup is None:
        module.fail_json(
            msg="Specified protection group {0} does not exist.".format(
                module.params["name"]
            )
        )


if __name__ == "__main__":
    main()
