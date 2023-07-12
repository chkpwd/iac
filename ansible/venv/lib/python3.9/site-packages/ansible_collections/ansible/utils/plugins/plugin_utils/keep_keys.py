#
# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#

"""
The keep_keys plugin code
"""
from __future__ import absolute_import, division, print_function


__metaclass__ = type

import re

from ansible.errors import AnsibleFilterError


def _raise_error(msg):
    """Raise an error message, prepend with filter name
    :param msg: The message
    :type msg: str
    :raises: AnsibleError
    """
    error = "Error when using plugin 'keep_keys': {msg}".format(msg=msg)
    raise AnsibleFilterError(error)


def keep_keys_from_dict_n_list(data, target, matching_parameter):
    if isinstance(data, list):
        list_data = [keep_keys_from_dict_n_list(each, target, matching_parameter) for each in data]
        return list_data
    if isinstance(data, dict):
        keep = {}
        for k, val in data.items():
            for key in target:
                match = None
                if not isinstance(val, (list, dict)):
                    if matching_parameter == "regex":
                        match = re.match(key, k)
                        if match:
                            keep[k] = val
                    elif matching_parameter == "starts_with":
                        if k.startswith(key):
                            keep[k], match = val, True
                    elif matching_parameter == "ends_with":
                        if k.endswith(key):
                            keep[k], match = val, True
                    else:
                        if k == key:
                            keep[k], match = val, True
                else:
                    list_data = keep_keys_from_dict_n_list(val, target, matching_parameter)
                    if isinstance(list_data, list) and not match:
                        list_data = [r for r in list_data if r not in ([], {})]
                        if all(isinstance(s, str) for s in list_data):
                            continue
                    if list_data in ([], {}):
                        continue
                    keep[k] = list_data
        return keep
    return data


def keep_keys(data, target, matching_parameter="equality"):
    """keep selective keys recursively from a given data"
    :param data: The data passed in (data|keep_keys(...))
    :type data: raw
    :param target: List of keys on with operation is to be performed
    :type data: list
    :type elements: string
    :param matching_parameter: matching type of the target keys with data keys
    :type data: str
    """
    if not isinstance(data, (list, dict)):
        _raise_error("Input is not valid for keep operation")
    data = keep_keys_from_dict_n_list(data, target, matching_parameter)
    return data
