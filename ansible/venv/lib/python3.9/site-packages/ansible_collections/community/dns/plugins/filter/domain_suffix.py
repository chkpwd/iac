# -*- coding: utf-8 -*-

# Copyright (c) 2020-2021, Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.community.dns.plugins.plugin_utils.public_suffix import PUBLIC_SUFFIX_LIST


def _remove_suffix(dns_name, suffix, keep_trailing_period):
    suffix_len = len(suffix)
    if suffix_len and suffix_len < len(dns_name) and not keep_trailing_period:
        suffix_len += 1
    return dns_name[:-suffix_len] if suffix_len else dns_name


def get_registrable_domain(dns_name,
                           keep_unknown_suffix=True,
                           only_if_registerable=True,
                           normalize_result=False,
                           icann_only=False):
    '''Given DNS name, returns the registrable domain.'''
    return PUBLIC_SUFFIX_LIST.get_registrable_domain(
        dns_name,
        keep_unknown_suffix=keep_unknown_suffix,
        only_if_registerable=only_if_registerable,
        normalize_result=normalize_result,
        icann_only=icann_only,
    )


def get_public_suffix(dns_name,
                      keep_leading_period=True,
                      keep_unknown_suffix=True,
                      normalize_result=False,
                      icann_only=False):
    '''Given DNS name, returns the public suffix.'''
    suffix = PUBLIC_SUFFIX_LIST.get_suffix(
        dns_name,
        keep_unknown_suffix=keep_unknown_suffix,
        normalize_result=normalize_result,
        icann_only=icann_only,
    )
    if suffix and len(suffix) < len(dns_name) and keep_leading_period:
        suffix = '.' + suffix
    return suffix


def remove_registrable_domain(dns_name,
                              keep_trailing_period=False,
                              keep_unknown_suffix=True,
                              only_if_registerable=True,
                              icann_only=False):
    '''Given DNS name, returns the part before the registrable_domain.'''
    suffix = PUBLIC_SUFFIX_LIST.get_registrable_domain(
        dns_name,
        keep_unknown_suffix=keep_unknown_suffix,
        only_if_registerable=only_if_registerable,
        normalize_result=False,
        icann_only=icann_only,
    )
    return _remove_suffix(dns_name, suffix, keep_trailing_period)


def remove_public_suffix(dns_name,
                         keep_trailing_period=False,
                         keep_unknown_suffix=True,
                         icann_only=False):
    '''Given DNS name, returns the part before the public suffix.'''
    suffix = PUBLIC_SUFFIX_LIST.get_suffix(
        dns_name,
        keep_unknown_suffix=keep_unknown_suffix,
        normalize_result=False,
        icann_only=icann_only,
    )
    return _remove_suffix(dns_name, suffix, keep_trailing_period)


class FilterModule(object):
    '''Ansible jinja2 filters'''

    def filters(self):
        return {
            'get_public_suffix': get_public_suffix,
            'get_registrable_domain': get_registrable_domain,
            'remove_public_suffix': remove_public_suffix,
            'remove_registrable_domain': remove_registrable_domain,
        }
