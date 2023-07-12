# -*- coding: utf-8 -*-

# (c) 2023, Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import time
import math

try:
    import fusion as purefusion
    from urllib3.exceptions import HTTPError
except ImportError:
    pass

from ansible_collections.purestorage.fusion.plugins.module_utils.errors import (
    OperationException,
)


def await_operation(fusion, operation, fail_playbook_if_operation_fails=True):
    """
    Waits for given operation to finish.
    Throws an exception by default if the operation fails.
    """
    op_api = purefusion.OperationsApi(fusion)
    operation_get = None
    while True:
        try:
            operation_get = op_api.get_operation(operation.id)
            if operation_get.status == "Succeeded":
                return operation_get
            if operation_get.status == "Failed":
                if fail_playbook_if_operation_fails:
                    raise OperationException(operation_get)
                return operation_get
        except HTTPError as err:
            raise OperationException(operation, http_error=err)
        time.sleep(int(math.ceil(operation_get.retry_in / 1000)))
