from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def underscore_to_hyphen(data):
    '''Recursively replace underscores in input object keys to hyphens '''
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data
