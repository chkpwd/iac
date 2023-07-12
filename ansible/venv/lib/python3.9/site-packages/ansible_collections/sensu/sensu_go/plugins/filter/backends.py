# -*- coding: utf-8 -*-
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


def _format_backend(vars):
    if "api_key_file" in vars:
        protocol = "wss"
    else:
        protocol = "ws"
    return "{0}://{1}:{2}".format(protocol, vars["inventory_hostname"], 8081)


def backends(hostvars, groups):
    return [
        _format_backend(hostvars[name]) for name in groups.get("backends", [])
    ]


class FilterModule(object):
    def filters(self):
        return dict(
            backends=backends,
        )
