# -*- coding: utf-8 -*-

# (c) 2023, Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import ipaddress

# while regexes are hard to maintain, they are used anyways for few reasons:
# a) REST backend accepts fairly restricted input and we need to match that input instead of all
#       the esoteric extra forms various packages are usually capable of parsing (like dotted-decimal
#       subnet masks, octal octets, hexadecimal octets, zero-extended addresses etc.)
# b) manually written parsing routines are usually complex to write, verify and think about
import re

# IPv4 octet regex part, matches only simple decimal 0-255 without leading zeroes
_octet = (
    "((?:[0-9])|"  # matches 0-9
    "(?:[1-9][0-9])|"  # matches 10-99
    "(?:1[0-9][0-9])|"  # matches 100-199
    "(?:2[0-4][0-9])|"  # matches 200-249
    "(?:25[0-5]))"  # matches 250-255
)

# IPv4 subnet mask regex part, matches decimal 8-32
_subnet_mask = (
    "((?:[8-9])|"  # matches 8-9
    "(?:[1-2][0-9])|"  # matches 10-29
    "(?:3[0-2]))"  # matches 30-32
)

# matches IPv4 addresses
_addr_pattern = re.compile(r"^{octet}\.{octet}\.{octet}\.{octet}$".format(octet=_octet))
# matches IPv4 networks in CIDR format, i.e. addresses in the form 'a.b.c.d/e'
_cidr_pattern = re.compile(
    r"^{octet}\.{octet}\.{octet}\.{octet}\/{0}$".format(_subnet_mask, octet=_octet)
)


def is_valid_network(addr):
    """Returns True if `addr` is IPv4 address/submask in bit CIDR notation, False otherwise."""
    match = re.match(_cidr_pattern, addr)
    if match is None:
        return False
    for i in range(4):
        if int(match.group(i + 1)) > 255:
            return False
    mask = int(match.group(5))
    if mask < 8 or mask > 32:
        return False
    return True


def is_valid_address(addr):
    """Returns True if `addr` is a valid IPv4 address, False otherwise. Does not support
    octal/hex notations."""
    match = re.match(_addr_pattern, addr)
    if match is None:
        return False
    for i in range(4):
        if int(match.group(i + 1)) > 255:
            return False
    return True


def is_address_in_network(addr, network):
    """Returns True if `addr` and `network` are a valid IPv4 address and
    IPv4 network respectively and if `addr` is in `network`, False otherwise."""
    if not is_valid_address(addr) or not is_valid_network(network):
        return False
    parsed_addr = ipaddress.ip_address(addr)
    parsed_net = ipaddress.ip_network(network)
    return parsed_addr in parsed_net
