# -*- coding: utf-8 -*-

# (c) 2023, Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import re
import importlib
import importlib.metadata

# This file exists because Ansible currently cannot declare dependencies on Python modules.
# see https://github.com/ansible/ansible/issues/62733 for more info about lack of req support

#############################

# 'module_name, package_name, version_requirements' triplets
DEPENDENCIES = [
    ("fusion", "purefusion", ">=1.0.11,<2.0"),
    ("urllib3", "urllib3", None),
]

#############################


def _parse_version(val):
    """
    Parse a package version.
    Takes in either MAJOR.MINOR or MAJOR.MINOR.PATCH form. PATCH
    can have additional suffixes, e.g. '-prerelease', 'a1', ...

    :param val: a string representation of the package version
    :returns: tuple of ints (MAJOR, MINOR, PATCH) or None if not parsed
    """
    # regexes for this were really ugly
    try:
        parts = val.split(".")
        if len(parts) < 2 or len(parts) > 3:
            return None
        major = int(parts[0])
        minor = int(parts[1])
        if len(parts) > 2:
            patch = re.match(r"^\d+", parts[2])
            patch = int(patch.group(0))
        else:
            patch = None
        return (major, minor, patch)
    except Exception:
        return None


# returns list of tuples [(COMPARATOR, (MAJOR, MINOR, PATCH)),...]
def _parse_version_requirements(val):
    """
    Parse package requirements.

    :param val: a string in the form ">=1.0.11,<2.0"
    :returns: list of tuples in the form [(">=", (1, 0, 11)), ("<", (2, 0, None))] or None if not parsed
    """
    reqs = []
    try:
        parts = val.split(",")
        for part in parts:
            match = re.match(r"\s*(>=|<=|==|=|<|>|!=)\s*([^\s]+)", part)
            op = match.group(1)
            ver = match.group(2)
            ver_tuple = _parse_version(ver)
            if not ver_tuple:
                raise ValueError("invalid version {0}".format(ver))
            reqs.append((op, ver_tuple))
        return reqs
    except Exception as e:
        raise ValueError("invalid version requirement '{0}' {1}".format(val, e))


def _compare_version(op, ver, req):
    """
    Compare two versions.

    :param op: a string, one of comparators ">=", "<=", "=", "==", ">" or "<"
    :param ver: version tuple in _parse_version() return form
    :param req: version tuple in _parse_version() return form
    :returns: True if ver 'op' req; False otherwise
    """

    def _cmp(a, b):
        return (a > b) - (a < b)

    major = _cmp(ver[0], req[0])
    minor = _cmp(ver[1], req[1])
    patch = None
    if req[2] is not None:
        patch = _cmp(ver[2] or 0, req[2])
    result = {
        ">=": major > 0 or (major == 0 and (minor > 0 or patch is None or patch >= 0)),
        "<=": major < 0 or (major == 0 and (minor < 0 or patch is None or patch <= 0)),
        ">": major > 0
        or (major == 0 and (minor > 0 or patch is not None and patch > 0)),
        "<": major < 0
        or (major == 0 and (minor < 0 or patch is not None and patch < 0)),
        "=": major == 0 and minor == 0 and (patch is None or patch == 0),
        "==": major == 0 and minor == 0 and (patch is None or patch == 0),
        "!=": major != 0 or minor != 0 or (patch is not None and patch != 0),
    }.get(op)
    return result


def _version_satisfied(version, requirements):
    """
    Checks whether version matches given version requirements.

    :param version: a string, in input form to _parse_version()
    :param requirements: as string, in input form to _parse_version_requirements()
    :returns: True if 'version' matches 'requirements'; False otherwise
    """

    version = _parse_version(version)
    requirements = _parse_version_requirements(requirements)
    for req in requirements:
        if not _compare_version(req[0], version, req[1]):
            return False
    return True


# poor helper to work around the fact Ansible is unable to manage python dependencies
def _check_import(ansible_module, module, package=None, version_requirements=None):
    """
    Tries to import a module and optionally validates its package version.
    Calls AnsibleModule.fail_json() if not satisfied.

    :param ansible_module: an AnsibleModule instance
    :param module: a string with module name to try to import
    :param package: a string, package to check version for; must be specified with 'version_requirements'
    :param version_requirements: a string, version requirements for 'package'
    """
    try:
        mod = importlib.import_module(module)
    except ImportError:
        ansible_module.fail_json(
            msg="Error: Python package '{0}' required and missing".format(module)
        )

    if package and version_requirements:
        # silently ignore version checks and hope for the best if we can't fetch
        # the package version since we can't know how the user installs packages
        try:
            version = importlib.metadata.version(package)
            if version and not _version_satisfied(version, version_requirements):
                ansible_module.fail_json(
                    msg="Error: Python package '{0}' version '{1}' does not satisfy requirements '{2}'".format(
                        module, version, version_requirements
                    )
                )
        except Exception:
            pass  # ignore package loads


def check_dependencies(ansible_module):
    for module, package, version_requirements in DEPENDENCIES:
        _check_import(ansible_module, module, package, version_requirements)
