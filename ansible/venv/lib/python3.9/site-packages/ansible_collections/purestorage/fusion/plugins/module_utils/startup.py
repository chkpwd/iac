# -*- coding: utf-8 -*-

# (c) 2023, Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from ansible_collections.purestorage.fusion.plugins.module_utils.errors import (
    install_fusion_exception_hook,
)

from ansible_collections.purestorage.fusion.plugins.module_utils.prerequisites import (
    check_dependencies,
)

from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    get_fusion,
)


def setup_fusion(module):
    check_dependencies(module)
    install_fusion_exception_hook(module)
    return get_fusion(module)
