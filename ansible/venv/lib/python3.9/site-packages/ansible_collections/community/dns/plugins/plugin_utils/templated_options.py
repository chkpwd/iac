# -*- coding: utf-8 -*-
#
# Copyright (c) 2022 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class TemplatedOptionProvider(object):
    def __init__(self, plugin, templar):
        self.plugin = plugin
        self.templar = templar

    def get_option(self, option_name):
        value = self.plugin.get_option(option_name)
        if self.templar.is_template(value):
            value = self.templar.template(variable=value, disable_lookups=False)
        return value
