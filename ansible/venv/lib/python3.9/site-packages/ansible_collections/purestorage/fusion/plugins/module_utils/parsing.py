# -*- coding: utf-8 -*-

# (c) 2023, Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
import re

__metaclass__ = type

METRIC_SUFFIXES = ["K", "M", "G", "T", "P"]

duration_pattern = re.compile(
    r"^((?P<Y>[1-9]\d*)Y)?((?P<W>[1-9]\d*)W)?((?P<D>[1-9]\d*)D)?(((?P<H>[1-9]\d*)H)?((?P<M>[1-9]\d*)M)?)?$"
)
duration_transformation = {
    "Y": 365 * 24 * 60,
    "W": 7 * 24 * 60,
    "D": 24 * 60,
    "H": 60,
    "M": 1,
}


def parse_number_with_metric_suffix(module, number, factor=1024):
    """Given a human-readable string (e.g. 2G, 30M, 400),
    return the resolved integer.
    Will call `module.fail_json()` for invalid inputs.
    """
    try:
        stripped_num = number.strip()
        if stripped_num[-1].isdigit():
            return int(stripped_num)
        # has unit prefix
        result = float(stripped_num[:-1])
        suffix = stripped_num[-1].upper()
        factor_count = METRIC_SUFFIXES.index(suffix) + 1
        for _i in range(0, factor_count):
            result = result * float(factor)
        return int(result)
    except Exception:
        module.fail_json(
            msg="'{0}' is not a valid number, use '400', '1K', '2M', ...".format(number)
        )
    return 0


def parse_duration(period):
    if period.isdigit():
        return int(period)

    match = duration_pattern.match(period.upper())
    if not match or period == "":
        raise ValueError("Invalid format")

    durations = {
        "Y": int(match.group("Y")) if match.group("Y") else 0,
        "W": int(match.group("W")) if match.group("W") else 0,
        "D": int(match.group("D")) if match.group("D") else 0,
        "H": int(match.group("H")) if match.group("H") else 0,
        "M": int(match.group("M")) if match.group("M") else 0,
    }
    return sum(value * duration_transformation[key] for key, value in durations.items())


def parse_minutes(module, period):
    try:
        return parse_duration(period)
    except ValueError:
        module.fail_json(
            msg=(
                "'{0}' is not a valid time period, use combination of data units (Y,W,D,H,M)"
                "e.g. 4W3D5H, 5D8H5M, 3D, 5W, 1Y5W..."
            ).format(period)
        )
