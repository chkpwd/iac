# -*- coding: utf-8 -*-

# (c) 2023, Jan Kodera (jkodera@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

try:
    import fusion as purefusion
    import urllib3
except ImportError:
    pass

import sys
import json
import re
import traceback as trace


class OperationException(Exception):
    """Raised if an asynchronous Operation fails."""

    def __init__(self, op, http_error=None):
        self._op = op
        self._http_error = http_error

    @property
    def op(self):
        return self._op

    @property
    def http_error(self):
        return self._http_error


def _get_verbosity(module):
    # verbosity is a private member and Ansible does not really allow
    # providing extra information only if the user wants it due to ideological
    # reasons, so extract it as carefully as possible and assume non-verbose
    # if something fails
    try:
        if module._verbosity is not None and isinstance(module._verbosity, int):
            return module._verbosity
    except Exception:
        pass
    return 0


def _extract_rest_call_site(traceback):
    # extracts first function in traceback that comes from 'fusion.api.*_api*',
    # converts its name from something like 'get_volume' to 'Get volume' and returns
    while traceback:
        try:
            frame = traceback.tb_frame
            func_name = (
                frame.f_code.co_name
            )  # contains function name, e.g. 'get_volume'
            mod_path = frame.f_globals[
                "__name__"
            ]  # contains module path, e.g. 'fusion.api.volumes_api'
            path_segments = mod_path.split(".")
            if (
                path_segments[0] == "fusion"
                and path_segments[1] == "api"
                and "_api" in path_segments[2]
            ):
                call_site = func_name.replace("_", " ").capitalize()
                return call_site
        except Exception:
            pass
        traceback = traceback.tb_next
    return None


class DetailsPrinter:
    def __init__(self, target):
        self._target = target
        self._parenthesed = False

    def append(self, what):
        if not self._parenthesed:
            self._target += " ("
            self._parenthesed = True
        else:
            self._target += ", "

        self._target += what

    def finish(self):
        if self._parenthesed:
            self._target += ")"
        return self._target


def format_fusion_api_exception(exception, traceback=None):
    """Formats `fusion.rest.ApiException` into a simple short form, suitable
    for Ansible error output. Returns a (message: str, body: dict) tuple."""
    message = None
    code = None
    resource_name = None
    request_id = None
    body = None
    call_site = _extract_rest_call_site(traceback)
    try:
        body = json.loads(exception.body)
        request_id = body.get("request_id", None)
        error = body["error"]
        message = error.get("message")
        code = error.get("pure_code")
        if not code:
            code = exception.status
        if not code:
            code = error.get("http_code")
        resource_name = error["details"]["name"]
    except Exception:
        pass

    output = ""
    if call_site:
        output += "'{0}' failed".format(call_site)
    else:
        output += "request failed"

    if message:
        output += ", {0}".format(message.replace('"', "'"))

    details = DetailsPrinter(output)
    if resource_name:
        details.append("resource: '{0}'".format(resource_name))
    if code:
        details.append("code: '{0}'".format(code))
    if request_id:
        details.append("request id: '{0}'".format(request_id))
    output = details.finish()

    return (output, body)


def format_failed_fusion_operation_exception(exception):
    """Formats failed `fusion.Operation` into a simple short form, suitable
    for Ansible error output. Returns a (message: str, body: dict) tuple."""
    op = exception.op
    http_error = exception.http_error
    if op.status != "Failed" and not http_error:
        raise ValueError(
            "BUG: can only format Operation exception with .status == Failed or http_error != None"
        )

    message = None
    code = None
    operation_name = None
    operation_id = None

    try:
        if op.status == "Failed":
            operation_id = op.id
            error = op.error
            message = error.message
            code = error.pure_code
            if not code:
                code = error.http_code
        operation_name = op.request_type
    except Exception as e:
        pass

    output = ""
    if operation_name:
        # converts e.g. 'CreateVolume' to 'Create volume'
        operation_name = re.sub("(.)([A-Z][a-z]+)", r"\1 \2", operation_name)
        operation_name = re.sub(
            "([a-z0-9])([A-Z])", r"\1 \2", operation_name
        ).capitalize()
        output += "{0}: ".format(operation_name)
    output += "operation failed"

    if message:
        output += ", {0}".format(message.replace('"', "'"))

    details = DetailsPrinter(output)
    if code:
        details.append("code: '{0}'".format(code))
    if operation_id:
        details.append("operation id: '{0}'".format(operation_id))
    if http_error:
        details.append("HTTP error: '{0}'".format(str(http_error).replace('"', "'")))

    output = details.finish()

    return output


def format_http_exception(exception, traceback):
    """Formats failed `urllib3.exceptions` exceptions into a simple short form,
    suitable for Ansible error output. Returns a `str`."""
    # urllib3 exceptions hide all details in a formatted message so all we
    # can do is append the REST call that caused this
    output = ""
    call_site = _extract_rest_call_site(traceback)
    if call_site:
        output += "'{0}': ".format(call_site)
    output += "HTTP request failed via "

    inner = exception
    while True:
        try:
            e = inner.reason
            if e and isinstance(e, urllib3.exceptions.HTTPError):
                inner = e
                continue
            break
        except Exception:
            break

    if inner != exception:
        output += "'{0}'/'{1}'".format(type(inner).__name__, type(exception).__name__)
    else:
        output += "'{0}'".format(type(exception).__name__)

    output += " - {0}".format(str(exception).replace('"', "'"))

    return output


def _handle_api_exception(
    module,
    exception,
    traceback,
    verbosity,
):
    (error_message, body) = format_fusion_api_exception(exception, traceback)

    if verbosity > 1:
        module.fail_json(msg=error_message, call_details=body, traceback=str(traceback))
    elif verbosity > 0:
        module.fail_json(msg=error_message, call_details=body)
    else:
        module.fail_json(msg=error_message)


def _handle_operation_exception(module, exception, traceback, verbosity):
    op = exception.op

    error_message = format_failed_fusion_operation_exception(exception)

    if verbosity > 1:
        module.fail_json(
            msg=error_message, op_details=op.to_dict(), traceback=str(traceback)
        )
    elif verbosity > 0:
        module.fail_json(msg=error_message, op_details=op.to_dict())
    else:
        module.fail_json(msg=error_message)


def _handle_http_exception(module, exception, traceback, verbosity):
    error_message = format_http_exception(exception, traceback)

    if verbosity > 1:
        module.fail_json(msg=error_message, traceback=trace.format_exception(exception))
    else:
        module.fail_json(msg=error_message)


def _except_hook_callback(module, original_hook, type, value, traceback):
    verbosity = _get_verbosity(module)
    if type == purefusion.rest.ApiException:
        _handle_api_exception(
            module,
            value,
            traceback,
            verbosity,
        )
    elif type == OperationException:
        _handle_operation_exception(module, value, traceback, verbosity)
    elif issubclass(type, urllib3.exceptions.HTTPError):
        _handle_http_exception(module, value, traceback, verbosity)

    # if we bubbled here the handlers were not able to process the exception
    original_hook(type, value, traceback)


def install_fusion_exception_hook(module):
    """Installs a hook that catches `purefusion.rest.ApiException` and
    `OperationException` and produces simpler and nicer error messages
    for Ansible output."""
    original_hook = sys.excepthook
    sys.excepthook = lambda type, value, traceback: _except_hook_callback(
        module, original_hook, type, value, traceback
    )
