from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
import re


IP_PREFIX = re.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")


def bits(netmask):
    count = 0
    while (netmask):
        count += netmask & 1
        netmask >>= 1
    return count


def is_same_ip_address(current_ip, applied_ip):
    '''
    current_ip can be either an ip of type str or ip and subnet of tye list
    ip like "10.10.10.0"
    ip with subnet mask: ["10.10.10.0", "255.255.255.0"]

    applied_ip can be in 3 formats:
    2 same as above and
    "10.10.10.0/24"
    '''
    if type(current_ip) is list:
        current_ip = ' '.join(current_ip)
    if len(current_ip) == 0 and len(applied_ip) == 0:
        return True
    if len(current_ip) == 0 or len(applied_ip) == 0:
        return False
    if ' ' not in applied_ip and '/' not in applied_ip:
        return current_ip == applied_ip

    splitted_current_ip = [current_ip]
    splitted_applied_ip = [applied_ip]
    total_bits_current_ip = 0
    total_bits_applied_ip = 0

    if ' ' in current_ip:
        splitted_current_ip = current_ip.split(' ')
    elif '/' in current_ip:
        splitted_current_ip = current_ip.split('/')

    if ' ' in applied_ip:
        splitted_applied_ip = applied_ip.split(' ')
    elif '/' in applied_ip:
        splitted_applied_ip = applied_ip.split('/')

    if splitted_current_ip[0] != splitted_applied_ip[0]:
        return False
    else:
        if '.' in splitted_current_ip[1]:
            total_bits_current_ip = sum([bits(int(s)) for s in splitted_current_ip[1].split('.')])
        else:
            total_bits_current_ip = int(splitted_current_ip[1])

        if '.' in splitted_applied_ip[1]:
            total_bits_applied_ip = sum([bits(int(s)) for s in splitted_applied_ip[1].split('.')])
        else:
            total_bits_applied_ip = int(splitted_applied_ip[1])

        return total_bits_current_ip == total_bits_applied_ip


def is_same_comparison(reorder_current, reorder_filtered):
    for key, value in reorder_filtered.items():
        if key not in reorder_current:
            return False

        if type(value) == dict:
            if not is_same_comparison(reorder_current[key], value):
                return False
        elif type(value) == list:
            if len(value) != len(reorder_current[key]):
                return False
            if len(value) and type(value[0]) == dict:
                for current_dict in reorder_current[key]:
                    if not is_same_comparison(current_dict, value[0]):
                        return False
            elif reorder_current[key] != value:
                return False
        elif type(value) == str and IP_PREFIX.match(value):
            return is_same_ip_address(reorder_current[key], value)

        elif reorder_current[key] != value:
            return False

    return True


def serialize(data):
    if type(data) == str and ' ' in data:
        return serialize(data.split(' '))
    if type(data) == list and len(data) > 0:
        if type(data[0]) == dict:
            list_to_order = []
            for dt in data:
                ret = {}
                for key, value in dt.items():
                    ret[key] = serialize(value)
                list_to_order.append(ret)

            return sorted(list_to_order, key=lambda dt: str(dt.items()))
        else:
            return sorted(data)

    if type(data) == dict:
        result = {}
        for key, value in data.items():
            result[key] = serialize(value)

        return result

    return data


def validate_result(result, desc):
    if not result:
        raise AssertionError("failed on test " + desc)


if __name__ == '__main__':
    validate_result(is_same_ip_address("10.29.0.0", "10.29.0.0"), "ip only")
    validate_result(is_same_ip_address("10.29.0.0/24", "10.29.0.0/24"), 'slash and slash')
    validate_result(is_same_ip_address("11.11.10.0 255.255.254.0", "11.11.10.0/23"), 'slash and space')
    validate_result(is_same_ip_address("10.29.0.0/24", "10.29.0.0 255.255.255.0"), 'slash and space')
    validate_result(is_same_ip_address("10.29.0.0/24", "10.29.0.0 255.255.255.0"), 'slash and space')
    validate_result(is_same_ip_address("10.29.0.0", "10.29.0.0"), 'ip only')
    validate_result(is_same_ip_address("10.29.0.0 255.255.255.0", "10.29.0.0 255.255.255.0"), 'space and space')
    validate_result(is_same_ip_address("10.29.0.0 255.255.255.0", "10.29.0.0 255.255.255.0"), 'space and space')
    validate_result(is_same_ip_address("10.29.0.0 255.255.255.0", "10.29.0.0 255.255.255.0"), 'space and space')
    validate_result(is_same_ip_address(["10.29.0.0", "255.255.255.0"], "10.29.0.0 255.255.255.0"), 'space and space')
    validate_result(is_same_ip_address(["10.29.0.0", "255.255.255.0"], "10.29.0.0/24"), 'space and space')
