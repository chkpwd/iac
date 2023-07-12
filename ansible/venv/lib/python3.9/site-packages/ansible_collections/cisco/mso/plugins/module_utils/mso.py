# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
import re
import os
import ast
import datetime
import shutil
import tempfile
from ansible.module_utils.basic import json
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import PY3
from ansible.module_utils.six.moves import filterfalse
from ansible.module_utils.six.moves.urllib.parse import urlencode, urljoin
from ansible.module_utils.urls import fetch_url
from ansible.module_utils._text import to_native, to_text
from ansible.module_utils.connection import Connection
from ansible_collections.cisco.mso.plugins.module_utils.constants import NDO_API_VERSION_PATH_FORMAT

try:
    from requests_toolbelt.multipart.encoder import MultipartEncoder

    HAS_MULTIPART_ENCODER = True
except ImportError:
    HAS_MULTIPART_ENCODER = False


if PY3:

    def cmp(a, b):
        return (a > b) - (a < b)


def issubset(subset, superset):
    """Recurse through nested dictionary and compare entries"""

    # Both objects are the same object
    if subset is superset:
        return True

    # Both objects are identical
    if subset == superset:
        return True

    # Both objects have a different type
    if type(subset) != type(superset):
        return False

    for key, value in subset.items():
        # Ignore empty values
        if value is None:
            return True

        # Item from subset is missing from superset
        if key not in superset:
            return False

        # Item has different types in subset and superset
        if type(superset.get(key)) != type(value):
            return False

        # Compare if item values are subset
        if isinstance(value, dict):
            if not issubset(superset.get(key), value):
                return False
        elif isinstance(value, list):
            try:
                # NOTE: Fails for lists of dicts
                if not set(value) <= set(superset.get(key)):
                    return False
            except TypeError:
                # Fall back to exact comparison for lists of dicts
                diff = list(filterfalse(lambda i: i in value, superset.get(key))) + list(filterfalse(lambda j: j in superset.get(key), value))
                if diff:
                    return False
        elif isinstance(value, set):
            if not value <= superset.get(key):
                return False
        else:
            if not value == superset.get(key):
                return False

    return True


def update_qs(params):
    """Append key-value pairs to self.filter_string"""
    accepted_params = dict((k, v) for (k, v) in params.items() if v is not None)
    return "?" + urlencode(accepted_params)


def mso_argument_spec():
    return dict(
        host=dict(type="str", required=False, aliases=["hostname"], fallback=(env_fallback, ["MSO_HOST"])),
        port=dict(type="int", required=False, fallback=(env_fallback, ["MSO_PORT"])),
        username=dict(type="str", required=False, fallback=(env_fallback, ["MSO_USERNAME", "ANSIBLE_NET_USERNAME"])),
        password=dict(type="str", required=False, no_log=True, fallback=(env_fallback, ["MSO_PASSWORD", "ANSIBLE_NET_PASSWORD"])),
        output_level=dict(type="str", default="normal", choices=["debug", "info", "normal"], fallback=(env_fallback, ["MSO_OUTPUT_LEVEL"])),
        timeout=dict(type="int", default=30, fallback=(env_fallback, ["MSO_TIMEOUT"])),
        use_proxy=dict(type="bool", fallback=(env_fallback, ["MSO_USE_PROXY"])),
        use_ssl=dict(type="bool", fallback=(env_fallback, ["MSO_USE_SSL"])),
        validate_certs=dict(type="bool", fallback=(env_fallback, ["MSO_VALIDATE_CERTS"])),
        login_domain=dict(type="str", fallback=(env_fallback, ["MSO_LOGIN_DOMAIN"])),
    )


def mso_reference_spec():
    return dict(
        name=dict(type="str", required=True),
        schema=dict(type="str"),
        template=dict(type="str"),
    )


def mso_epg_subnet_spec():
    return dict(
        subnet=dict(type="str", required=True, aliases=["ip"]),
        description=dict(type="str"),
        scope=dict(type="str", default="private", choices=["private", "public"]),
        shared=dict(type="bool", default=False),
        no_default_gateway=dict(type="bool", default=False),
    )


def mso_subnet_spec():
    subnet_spec = mso_epg_subnet_spec()
    subnet_spec.update(dict(querier=dict(type="bool", default=False)))
    return subnet_spec


def mso_bd_subnet_spec():
    subnet_spec = mso_epg_subnet_spec()
    subnet_spec.update(dict(querier=dict(type="bool", default=False)))
    subnet_spec.update(dict(primary=dict(type="bool", default=False)))
    subnet_spec.update(dict(virtual=dict(type="bool", default=False)))
    return subnet_spec


def mso_dhcp_spec():
    return dict(
        dhcp_option_policy=dict(type="dict", options=mso_dhcp_option_spec()),
        name=dict(type="str", required=True),
        version=dict(type="int", required=True),
    )


def mso_dhcp_option_spec():
    return dict(
        name=dict(type="str", required=True),
        version=dict(type="int", required=True),
    )


def mso_contractref_spec():
    return dict(
        name=dict(type="str", required=True),
        schema=dict(type="str"),
        template=dict(type="str"),
        type=dict(type="str", required=True, choices=["consumer", "provider"]),
    )


def mso_expression_spec():
    return dict(
        type=dict(type="str", required=True, aliases=["tag"]),
        operator=dict(type="str", choices=["not_in", "in", "equals", "not_equals", "has_key", "does_not_have_key"], required=True),
        value=dict(type="str"),
    )


def mso_expression_spec_ext_epg():
    return dict(
        type=dict(type="str", choices=["ip_address"], required=True),
        operator=dict(type="str", choices=["equals"], required=True),
        value=dict(type="str", required=True),
    )


def mso_hub_network_spec():
    return dict(
        name=dict(type="str", required=True),
        tenant=dict(type="str", required=True),
    )


def mso_object_migrate_spec():
    return dict(
        epg=dict(type="str", required=True),
        anp=dict(type="str", required=True),
    )


def mso_service_graph_node_spec():
    return dict(
        type=dict(type="str", required=True),
    )


def mso_service_graph_node_device_spec():
    return dict(
        name=dict(type="str", required=True),
    )


def mso_service_graph_connector_spec():
    return dict(
        provider=dict(type="str", required=True),
        consumer=dict(type="str", required=True),
        # Only connectorType bd with value "general" is supported for now thus fixed in code
        #  when connectorType externalEpg is supported "route-peering" should be added
        #  also change SERVICE_NODE_CONNECTOR_TYPE_MAP in constants.py
        #  also verify if connector type is specific to provider or always same for both
        connector_object_type=dict(type="str", default="bd", choices=["bd"]),
        provider_schema=dict(type="str"),
        provider_template=dict(type="str"),
        consumer_schema=dict(type="str"),
        consumer_template=dict(type="str"),
    )


def mso_site_anp_epg_bulk_staticport_spec():
    return dict(
        type=dict(type="str", choices=["port", "vpc", "dpc"]),
        pod=dict(type="str"),  # This parameter is not required for querying all objects
        leaf=dict(type="str"),  # This parameter is not required for querying all objects
        fex=dict(type="str"),  # This parameter is not required for querying all objects
        path=dict(type="str"),  # This parameter is not required for querying all objects
        vlan=dict(type="int"),  # This parameter is not required for querying all objects
        primary_micro_segment_vlan=dict(type="int"),  # This parameter is not required for querying all objects
        deployment_immediacy=dict(type="str", choices=["immediate", "lazy"]),
        mode=dict(type="str", choices=["native", "regular", "untagged"]),
    )


# Copied from ansible's module uri.py (url): https://github.com/ansible/ansible/blob/cdf62edc65f564fff6b7e575e084026fa7faa409/lib/ansible/modules/uri.py
def write_file(module, url, dest, content, resp, tmpsrc=None):
    # create a tempfile with some test content

    if tmpsrc is None and content is not None:
        fd, tmpsrc = tempfile.mkstemp(dir=module.tmpdir)
        f = open(tmpsrc, "wb")
        try:
            f.write(content)
        except Exception as e:
            os.remove(tmpsrc)
            module.fail_json(msg="Failed to create temporary content file: {0}".format(to_native(e)))
        f.close()

    checksum_src = None
    checksum_dest = None

    # raise an error if there is no tmpsrc file
    if not os.path.exists(tmpsrc):
        os.remove(tmpsrc)
        module.fail_json(msg="Source '{0}' does not exist".format(tmpsrc))
    if not os.access(tmpsrc, os.R_OK):
        os.remove(tmpsrc)
        module.fail_json(msg="Source '{0}' is not readable".format(tmpsrc))
    checksum_src = module.sha1(tmpsrc)

    # check if there is no dest file
    if os.path.exists(dest):
        # raise an error if copy has no permission on dest
        if not os.access(dest, os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination '{0}' not writable".format(dest))
        if not os.access(dest, os.R_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination '{0}' not readable".format(dest))
        checksum_dest = module.sha1(dest)
    else:
        if not os.access(os.path.dirname(dest), os.W_OK):
            os.remove(tmpsrc)
            module.fail_json(msg="Destination dir '{0}' not writable".format(os.path.dirname(dest)))

    if checksum_src != checksum_dest:
        try:
            shutil.copyfile(tmpsrc, dest)
        except Exception as e:
            os.remove(tmpsrc)
            module.fail_json(msg="failed to copy {0} to {1}: {2}".format(tmpsrc, dest, to_native(e)))

    os.remove(tmpsrc)


class MSOModule(object):
    def __init__(self, module):
        self.module = module
        self.params = module.params
        self.result = dict(changed=False)
        self.headers = {"Content-Type": "text/json"}
        self.platform = "mso"

        # normal output
        self.existing = dict()

        # mso_rest output
        self.jsondata = None
        self.error = dict(code=None, message=None, info=None)

        # info output
        self.previous = dict()
        self.proposed = dict()
        self.sent = dict()
        self.stdout = None
        self.patch_operation = None

        # debug output
        self.has_modified = False
        self.filter_string = ""
        self.method = None
        self.path = None
        self.response = None
        self.status = None
        self.url = None
        self.httpapi_logs = list()

        if self.module._debug:
            self.module.warn("Enable debug output because ANSIBLE_DEBUG was set.")
            self.params["output_level"] = "debug"

        if self.module._socket_path is None:
            if self.params.get("use_ssl") is None:
                self.params["use_ssl"] = True
            if self.params.get("use_proxy") is None:
                self.params["use_proxy"] = True
            if self.params.get("validate_certs") is None:
                self.params["validate_certs"] = True

            # Ensure protocol is set
            self.params["protocol"] = "https" if self.params.get("use_ssl", True) else "http"

            # Set base_uri
            if self.params.get("port") is not None:
                self.base_only_uri = "{protocol}://{host}:{port}/".format(**self.params)
                self.baseuri = "{0}api/v1/".format(self.base_only_uri)
            else:
                self.base_only_uri = "{protocol}://{host}/".format(**self.params)
                self.baseuri = "{0}api/v1/".format(self.base_only_uri)

            if self.params.get("host") is None:
                self.fail_json(msg="Parameter 'host' is required when not using the HTTP API connection plugin")

            if self.params.get("password"):
                # Perform password-based authentication, log on using password
                self.login()
            else:
                self.fail_json(msg="Parameter 'password' is required for authentication")
        else:
            self.connection = Connection(self.module._socket_path)
            if self.connection.get_platform() == "cisco.nd":
                self.platform = "nd"

    def get_login_domain_id(self, domain):
        """Get a domain and return its id"""
        if domain is None:
            return domain
        d = self.get_obj("auth/login-domains", key="domains", name=domain)
        if not d:
            self.fail_json(msg="Login domain '%s' is not a valid domain name." % domain)
        if "id" not in d:
            self.fail_json(msg="Login domain lookup failed for domain '%s': %s" % (domain, d))
        return d["id"]

    def login(self):
        """Log in to MSO"""

        # Perform login request
        if (self.params.get("login_domain") is not None) and (self.params.get("login_domain") != "Local"):
            domain_id = self.get_login_domain_id(self.params.get("login_domain"))
            payload = {"username": self.params.get("username", "admin"), "password": self.params.get("password"), "domainId": domain_id}
        else:
            payload = {"username": self.params.get("username", "admin"), "password": self.params.get("password")}
        self.url = urljoin(self.baseuri, "auth/login")
        resp, auth = fetch_url(
            self.module,
            self.url,
            data=json.dumps(payload),
            method="POST",
            headers=self.headers,
            timeout=self.params.get("timeout"),
            use_proxy=self.params.get("use_proxy"),
        )

        # Handle MSO response
        if auth.get("status") not in [200, 201]:
            self.response = auth.get("msg")
            self.status = auth.get("status")
            self.fail_json(msg="Authentication failed: {msg}".format(**auth))

        payload = json.loads(resp.read())

        self.headers["Authorization"] = "Bearer {token}".format(**payload)

    def response_json(self, rawoutput):
        """Handle MSO JSON response output"""
        try:
            self.jsondata = json.loads(rawoutput)
        except Exception as e:
            # Expose RAW output for troubleshooting
            self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. %s" % e)
            self.result["raw"] = rawoutput
            return

        # Handle possible MSO error information
        if self.status not in [200, 201, 202, 204]:
            self.error = self.jsondata

    def request_download(self, path, destination=None, method="GET", api_version="v1"):
        if self.platform != "nd":
            self.url = urljoin(self.baseuri, path)

        redirected = False
        redir_info = {}
        redirect = {}
        content = None
        data = None

        src = self.params.get("src")
        if src:
            try:
                self.headers.update({"Content-Length": os.stat(src).st_size})
                data = open(src, "rb")
            except OSError:
                self.fail_json(msg="Unable to open source file %s" % src, elapsed=0)

        kwargs = {}
        if destination is not None and os.path.isdir(destination):
            # first check if we are redirected to a file download
            if self.platform == "nd":
                redir_info = self.connection.get_remote_file_io_stream(
                    NDO_API_VERSION_PATH_FORMAT.format(api_version=api_version, path=path), self.module.tmpdir, method
                )
                # In place of Content-Disposition, NDO get_remote_file_io_stream returns content-disposition.
                content_disposition = redir_info.get("content-disposition")
            else:
                check, redir_info = fetch_url(self.module, self.url, headers=self.headers, method=method, timeout=self.params.get("timeout"))
                content_disposition = check.headers.get("Content-Disposition")

            if content_disposition:
                file_name = content_disposition.split("filename=")[1]
            else:
                self.fail_json(msg="Failed to fetch {0} backup information from MSO/NDO, response: {1}".format(self.params.get("backup"), redir_info))

            # if we are redirected, update the url with the location header and update dest with the new url filename
            if redir_info["status"] in (301, 302, 303, 307):
                self.url = redir_info.get("location")
                redirected = True
            destination = os.path.join(destination, file_name)

        # if destination file already exist, only download if file newer
        if os.path.exists(destination):
            kwargs["last_mod_time"] = datetime.datetime.utcfromtimestamp(os.path.getmtime(destination))

        if self.platform == "nd":
            if redir_info["status"] == 200 and redirected is False:
                info = redir_info
            else:
                info = self.connection.get_remote_file_io_stream("/mso/{0}".format(self.url.split("/mso/", 1)), self.module.tmpdir, method)
        else:
            resp, info = fetch_url(
                self.module,
                self.url,
                data=data,
                headers=self.headers,
                method=method,
                timeout=self.params.get("timeout"),
                unix_socket=self.params.get("unix_socket"),
                **kwargs
            )

            try:
                content = resp.read()
            except AttributeError:
                # there was no content, but the error read() may have been stored in the info as 'body'
                content = info.pop("body", "")

            if src:
                # Try to close the open file handle
                try:
                    data.close()
                except Exception:
                    pass

        redirect["redirected"] = redirected or info.get("url") != self.url
        redirect.update(redir_info)
        redirect.update(info)

        write_file(self.module, self.url, destination, content, redirect, info.get("tmpsrc"))

        return redirect, destination

    def request_upload(self, path, fields=None, method="POST", api_version="v1"):
        """Generic HTTP MultiPart POST method for MSO uploads."""
        self.path = path
        if self.platform != "nd":
            self.url = urljoin(self.baseuri, path)

        info = dict()

        if self.platform == "nd":
            try:
                if os.path.exists(self.params.get("backup")):
                    info = self.connection.send_file_request(
                        method,
                        NDO_API_VERSION_PATH_FORMAT.format(api_version=api_version, path=path),
                        file=self.params.get("backup"),
                        remote_path=self.params.get("remote_path"),
                    )
                else:
                    self.fail_json(msg="Upload failed due to: No such file or directory, Backup file: '{0}'".format(self.params.get("backup")))
            except Exception as error:
                self.fail_json("NDO upload failed due to: {0}".format(error))
        else:
            if not HAS_MULTIPART_ENCODER:
                self.fail_json(msg="requests-toolbelt is required for the upload state of this module")

            mp_encoder = MultipartEncoder(fields=fields)
            self.headers["Content-Type"] = mp_encoder.content_type
            self.headers["Accept-Encoding"] = "gzip, deflate, br"

            resp, info = fetch_url(
                self.module,
                self.url,
                headers=self.headers,
                data=mp_encoder,
                method=method,
                timeout=self.params.get("timeout"),
                use_proxy=self.params.get("use_proxy"),
            )

        self.response = info.get("msg")
        self.status = info.get("status")

        # Get change status from HTTP headers
        if "modified" in info:
            self.has_modified = True
            if info.get("modified") == "false":
                self.result["changed"] = False
            elif info.get("modified") == "true":
                self.result["changed"] = True

        # 200: OK, 201: Created, 202: Accepted, 204: No Content
        if self.status in (200, 201, 202, 204):
            if self.platform == "nd":
                return info
            else:
                output = resp.read()
                if output:
                    return json.loads(output)

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status:
            if self.status >= 400:
                try:
                    if self.platform == "nd":
                        payload = info.get("body")
                    else:
                        payload = json.loads(resp.read())
                except (ValueError, AttributeError):
                    try:
                        payload = json.loads(info.get("body"))
                    except Exception:
                        self.fail_json(msg="MSO Error:", info=info)
                if "code" in payload:
                    self.fail_json(msg="MSO Error {code}: {message}".format(**payload), info=info, payload=payload)
                else:
                    self.fail_json(msg="MSO Error:".format(**payload), info=info, payload=payload)
        else:
            self.fail_json(msg="Backup file upload failed due to: {0}".format(info))
        return {}

    def request(self, path, method=None, data=None, qs=None, api_version="v1"):
        """Generic HTTP method for MSO requests."""
        self.path = path

        if method is not None:
            self.method = method

        # If we PATCH with empty operations, return
        if method == "PATCH" and not data:
            return {}
        else:
            self.patch_operation = data

        # if method in ['PATCH', 'PUT']:
        #     if qs is not None:
        #         qs['enableVersionCheck'] = 'true'
        #     else:
        #         qs = dict(enableVersionCheck='true')

        if method in ["PATCH"]:
            if qs is not None:
                qs["validate"] = "false"
            else:
                qs = dict(validate="false")

        resp = None
        if self.module._socket_path:
            self.connection.set_params(self.params)
            if api_version is not None:
                uri = NDO_API_VERSION_PATH_FORMAT.format(api_version=api_version, path=self.path)
            else:
                uri = self.path

            if qs is not None:
                uri = uri + update_qs(qs)

            try:
                info = self.connection.send_request(method, uri, json.dumps(data))
                self.url = info.get("url")
                self.httpapi_logs.extend(self.connection.pop_messages())
                info.pop("date", None)
            except Exception as e:
                try:
                    error_obj = json.loads(to_text(e))
                except Exception:
                    error_obj = dict(
                        error=dict(code=-1, message="Unable to parse error output as JSON. Raw error message: {0}".format(e), exception=to_text(e))
                    )
                    pass
                self.fail_json(msg=error_obj["error"]["message"])

        else:
            if api_version is not None:
                self.url = "{0}api/{1}/{2}".format(self.base_only_uri, api_version, self.path.lstrip("/"))
            else:
                self.url = "{0}{1}".format(self.base_only_uri, self.path.lstrip("/"))

            if qs is not None:
                self.url = self.url + update_qs(qs)
            resp, info = fetch_url(
                self.module,
                self.url,
                headers=self.headers,
                data=json.dumps(data),
                method=self.method,
                timeout=self.params.get("timeout"),
                use_proxy=self.params.get("use_proxy"),
            )

        self.response = info.get("msg")
        self.status = info.get("status", -1)

        # Get change status from HTTP headers
        if "modified" in info:
            self.has_modified = True
            if info.get("modified") == "false":
                self.result["changed"] = False
            elif info.get("modified") == "true":
                self.result["changed"] = True

        # 200: OK, 201: Created, 202: Accepted
        if self.status in (200, 201, 202):
            try:
                output = resp.read()
                if output:
                    try:
                        return json.loads(output)
                    except Exception as e:
                        self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. {0}".format(e))
                        self.result["raw"] = output
                        return
            except AttributeError:
                return info.get("body")

        # 204: No Content
        elif self.status == 204:
            return {}

        # 404: Not Found
        elif self.method == "DELETE" and self.status == 404:
            return {}

        # 400: Bad Request, 401: Unauthorized, 403: Forbidden,
        # 405: Method Not Allowed, 406: Not Acceptable
        # 500: Internal Server Error, 501: Not Implemented
        elif self.status >= 400:
            self.result["status"] = self.status
            body = info.get("body")
            if body is not None:
                try:
                    if isinstance(body, dict):
                        payload = body
                    else:
                        payload = json.loads(body)
                except Exception as e:
                    self.error = dict(code=-1, message="Unable to parse output as JSON, see 'raw' output. %s" % e)
                    self.result["raw"] = body
                    self.fail_json(msg="MSO Error:", data=data, info=info)
                self.error = payload
                if "code" in payload:
                    self.fail_json(msg="MSO Error {code}: {message}".format(**payload), data=data, info=info, payload=payload)
                else:
                    self.fail_json(msg="MSO Error:".format(**payload), data=data, info=info, payload=payload)
            else:
                # Connection error
                msg = "Connection failed for {0}. {1}".format(info.get("url"), info.get("msg"))
                self.error = msg
                self.fail_json(msg=msg)
            return {}

    def query_objs(self, path, key=None, api_version="v1", **kwargs):
        """Query the MSO REST API for objects in a path"""
        found = []
        objs = self.request(path, api_version=api_version, method="GET")

        if objs == {} or objs == []:
            return found

        if key is None:
            key = path

        if isinstance(objs, dict):
            if key not in objs:
                self.fail_json(msg="Key '{0}' missing from data".format(key), data=objs)
            objs_list = objs.get(key)
        else:
            objs_list = objs
        for obj in objs_list:
            for kw_key, kw_value in kwargs.items():
                if kw_value is None:
                    continue
                if isinstance(kw_value, dict):
                    obj_value = obj.get(kw_key)
                    if obj_value is not None and isinstance(obj_value, dict):
                        breakout = False
                        for kw_key_lvl2, kw_value_lvl2 in kw_value.items():
                            if obj_value.get(kw_key_lvl2) != kw_value_lvl2:
                                breakout = True
                                break
                        if breakout:
                            break
                    else:
                        break
                elif obj.get(kw_key) != kw_value:
                    break
            else:
                found.append(obj)

        return found

    def query_obj(self, path, api_version="v1", **kwargs):
        """Query the MSO REST API for the whole object at a path"""
        obj = self.request(path, api_version=api_version, method="GET")
        if obj == {}:
            return {}
        for kw_key, kw_value in kwargs.items():
            if kw_value is None:
                continue
            if isinstance(kw_value, dict):
                obj_value = obj.get(kw_key)
                if obj_value is not None and isinstance(obj_value, dict):
                    for kw_key_lvl2, kw_value_lvl2 in kw_value.items():
                        if obj_value.get(kw_key_lvl2) != kw_value_lvl2:
                            return {}
            elif obj.get(kw_key) != kw_value:
                return {}
        return obj

    def get_obj(self, path, api_version="v1", **kwargs):
        """Get a specific object from a set of MSO REST objects"""
        objs = self.query_objs(path, api_version=api_version, **kwargs)
        if len(objs) == 0:
            return {}
        if len(objs) > 1:
            self.fail_json(msg="More than one object matches unique filter: {0}".format(kwargs))
        return objs[0]

    def lookup_schema(self, schema):
        """Look up schema and return its id"""
        if schema is None:
            return schema

        schema_summary = self.query_objs("schemas/list-identity", key="schemas", displayName=schema)
        if not schema_summary:
            self.fail_json(msg="Provided schema '{0}' does not exist.".format(schema))
        schema_id = schema_summary[0].get("id")
        if not schema_id:
            self.fail_json(msg="Schema lookup failed for schema '{0}': '{1}'".format(schema, schema_id))
        return schema_id

    def lookup_domain(self, domain):
        """Look up a domain and return its id"""
        if domain is None:
            return domain

        d = self.get_obj("auth/domains", key="domains", name=domain)
        if not d:
            self.fail_json(msg="Domain '%s' is not a valid domain name." % domain)
        if "id" not in d:
            self.fail_json(msg="Domain lookup failed for domain '%s': %s" % (domain, d))
        return d.get("id")

    def lookup_roles(self, roles):
        """Look up roles and return their ids"""
        if roles is None:
            return roles

        ids = []
        for role in roles:
            access_type = "readWrite"
            try:
                role = ast.literal_eval(role)
                if type(role) is dict and "name" in role:
                    name = role.get("name")
                    if role.get("access_type") == "read":
                        access_type = "readOnly"
            except ValueError:
                name = role

            r = self.get_obj("roles", name=name)
            if not r:
                self.fail_json(msg="Role '%s' is not a valid role name." % name)
            if "id" not in r:
                self.fail_json(msg="Role lookup failed for role '%s': %s" % (name, r))
            ids.append(dict(roleId=r.get("id"), accessType=access_type))
        return ids

    def lookup_site(self, site):
        """Look up a site and return its id"""
        if site is None:
            return site

        s = self.get_obj("sites", name=site)
        if not s:
            self.fail_json(msg="Site '%s' is not a valid site name." % site)
        if "id" not in s:
            self.fail_json(msg="Site lookup failed for site '%s': %s" % (site, s))
        return s.get("id")

    def lookup_sites(self, sites):
        """Look up sites and return their ids"""
        if sites is None:
            return sites

        ids = []
        for site in sites:
            s = self.get_obj("sites", name=site)
            if not s:
                self.fail_json(msg="Site '%s' is not a valid site name." % site)
            if "id" not in s:
                self.fail_json(msg="Site lookup failed for site '%s': %s" % (site, s))
            ids.append(dict(siteId=s.get("id"), securityDomains=[]))
        return ids

    def lookup_tenant(self, tenant):
        """Look up a tenant and return its id"""
        if tenant is None:
            return tenant

        t = self.get_obj("tenants", key="tenants", name=tenant)
        if not t:
            self.fail_json(msg="Tenant '%s' is not valid tenant name." % tenant)
        if "id" not in t:
            self.fail_json(msg="Tenant lookup failed for tenant '%s': %s" % (tenant, t))
        return t.get("id")

    def lookup_remote_location(self, remote_location):
        """Look up a remote location and return its path and id"""
        if remote_location is None:
            return None

        remote = self.get_obj("platform/remote-locations", key="remoteLocations", name=remote_location)
        if "id" not in remote:
            self.fail_json(msg="No remote location found for remote '%s'" % (remote_location))
        remote_info = dict(id=remote.get("id"), path=remote.get("credential")["remotePath"])
        return remote_info

    def lookup_users(self, users):
        """Look up users and return their ids"""
        # Ensure tenant has at least admin user
        if users is None:
            users = ["admin"]
        elif "admin" not in users:
            users.append("admin")

        ids = []
        for user in users:
            if self.platform == "nd":
                u = self.get_obj("users", loginID=user, api_version="v2")
            else:
                u = self.get_obj("users", username=user)
            if not u:
                self.fail_json(msg="User '%s' is not a valid user name." % user)
            if "id" not in u:
                if "userID" not in u:
                    self.fail_json(msg="User lookup failed for user '%s': %s" % (user, u))
                id = dict(userId=u.get("userID"))
            else:
                id = dict(userId=u.get("id"))
            if id in ids:
                self.fail_json(msg="User '%s' is duplicate." % user)
            ids.append(id)

        return ids

    def create_label(self, label, label_type):
        """Create a new label"""
        return self.request("labels", method="POST", data=dict(displayName=label, type=label_type))

    def lookup_labels(self, labels, label_type):
        """Look up labels and return their ids (create if necessary)"""
        if labels is None:
            return None

        ids = []
        for label in labels:
            label_obj = self.get_obj("labels", displayName=label)
            if not label_obj:
                label_obj = self.create_label(label, label_type)
            if "id" not in label_obj:
                self.fail_json(msg="Label lookup failed for label '%s': %s" % (label, label_obj))
            ids.append(label_obj.get("id"))
        return ids

    def anp_ref(self, **data):
        """Create anpRef string"""
        return "/schemas/{schema_id}/templates/{template}/anps/{anp}".format(**data)

    def epg_ref(self, **data):
        """Create epgRef string"""
        return "/schemas/{schema_id}/templates/{template}/anps/{anp}/epgs/{epg}".format(**data)

    def bd_ref(self, **data):
        """Create bdRef string"""
        return "/schemas/{schema_id}/templates/{template}/bds/{bd}".format(**data)

    def contract_ref(self, **data):
        """Create contractRef string"""
        # Support the contract argspec
        if "name" in data:
            data["contract"] = data.get("name")
        return "/schemas/{schema_id}/templates/{template}/contracts/{contract}".format(**data)

    def filter_ref(self, **data):
        """Create a filterRef string"""
        return "/schemas/{schema_id}/templates/{template}/filters/{filter}".format(**data)

    def vrf_ref(self, **data):
        """Create vrfRef string"""
        return "/schemas/{schema_id}/templates/{template}/vrfs/{vrf}".format(**data)

    def l3out_ref(self, **data):
        """Create l3outRef string"""
        return "/schemas/{schema_id}/templates/{template}/l3outs/{l3out}".format(**data)

    def ext_epg_ref(self, **data):
        """Create extEpgRef string"""
        return "/schemas/{schema_id}/templates/{template}/externalEpgs/{external_epg}".format(**data)

    def service_graph_ref(self, **data):
        """Create serviceGraphRef string"""
        return "/schemas/{schema_id}/templates/{template}/serviceGraphs/{service_graph}".format(**data)

    def vrf_dict_from_ref(self, data):
        vrf_ref_regex = re.compile(r"\/schemas\/(.*)\/templates\/(.*)\/vrfs\/(.*)")
        vrf_dict = vrf_ref_regex.search(data)
        return {
            "vrfName": vrf_dict.group(3),
            "schemaId": vrf_dict.group(1),
            "templateName": vrf_dict.group(2),
        }

    def dict_from_ref(self, data):
        if data and data != "":
            ref_regex = re.compile(r"\/schemas\/(.*)\/templates\/(.*?)\/(.*?)\/(.*)")
            dic = ref_regex.search(data)
            if dic is not None:
                schema_id = dic.group(1)
                template_name = dic.group(2)
                category = dic.group(3)
                name = dic.group(4)
                uri_map = {
                    "vrfs": ["vrfName", "schemaId", "templateName"],
                    "bds": ["bdName", "schemaId", "templateName"],
                    "filters": ["filterName", "schemaId", "templateName"],
                    "contracts": ["contractName", "schemaId", "templateName"],
                    "l3outs": ["l3outName", "schemaId", "templateName"],
                    "anps": ["anpName", "schemaId", "templateName"],
                    "serviceGraphs": ["serviceGraphName", "schemaId", "templateName"],
                    "serviceNode": ["serviceNodeName", "schemaId", "templateName", "serviceGraphName"],
                }
                result = {
                    uri_map[category][1]: schema_id,
                    uri_map[category][2]: template_name,
                }

                self.recursive_dict_from_ref_regex(name, result, uri_map[category][0])

                return result
            else:
                self.fail_json(msg="There was no group in search: {data}".format(data=data))

    def recursive_dict_from_ref_regex(self, data, result, category):
        continued_ref_regex = re.compile(r"(.*?)\/([a-zA-Z]+.*)")
        section_ref_regex = re.compile(r"([a-zA-Z]+)\/(.*)")
        dic_name = continued_ref_regex.search(data)
        if dic_name is not None:
            result[category] = dic_name.group(1)
            next_section = dic_name.group(2)
            dic_next_section = section_ref_regex.search(next_section)
            if dic_next_section is not None:
                next_name = dic_next_section.group(2)
                self.recursive_dict_from_ref_regex(next_name, result, dic_next_section.group(1).rstrip("s") + "Name")
        else:
            result[category] = data

    def recursive_dict_from_ref(self, data):
        for key in data:
            if key.endswith("Ref"):
                data[key] = self.dict_from_ref(data.get(key))
            if isinstance(data[key], list):
                for item in data[key]:
                    self.recursive_dict_from_ref(item)
        return data

    def make_reference(self, data, reftype, schema_id, template):
        """Create a reference from a dictionary"""
        # Removes entry from payload
        if data is None:
            return None

        if data.get("schema") is not None:
            schema_obj = self.get_obj("schemas", displayName=data.get("schema"))
            if not schema_obj:
                self.fail_json(msg="Referenced schema '{schema}' in {reftype}ref does not exist".format(reftype=reftype, **data))
            schema_id = schema_obj.get("id")

        if data.get("template") is not None:
            template = data.get("template")

        refname = "%sName" % reftype

        return {
            refname: data.get("name"),
            "schemaId": schema_id,
            "templateName": template,
        }

    def make_subnets(self, data, is_bd_subnet=True):
        """Create a subnets list from input"""
        if data is None:
            return None

        subnets = []
        for subnet in data:
            if "subnet" in subnet:
                subnet["ip"] = subnet.get("subnet")
            if subnet.get("description") is None:
                subnet["description"] = subnet.get("subnet")
            subnet_payload = dict(
                ip=subnet.get("ip"),
                description=str(subnet.get("description")),
                scope=subnet.get("scope"),
                shared=subnet.get("shared"),
                noDefaultGateway=subnet.get("no_default_gateway"),
            )
            if is_bd_subnet:
                subnet_payload.update(dict(querier=subnet.get("querier"), primary=subnet.get("primary"), virtual=subnet.get("virtual")))
            subnets.append(subnet_payload)

        return subnets

    def make_dhcp_label(self, data):
        """Create a DHCP policy from input"""
        if data is None:
            return None
        if type(data) == list:
            dhcps = []
            for dhcp in data:
                if "dhcp_option_policy" in dhcp:
                    dhcp["dhcpOptionLabel"] = dhcp.get("dhcp_option_policy")
                    del dhcp["dhcp_option_policy"]
                dhcps.append(dhcp)
            return dhcps
        if "version" in data:
            data["version"] = int(data.get("version"))
        if data and "dhcp_option_policy" in data:
            dhcp_option_policy = data.get("dhcp_option_policy")
            if dhcp_option_policy is not None and "version" in dhcp_option_policy:
                dhcp_option_policy["version"] = int(dhcp_option_policy.get("version"))
            data["dhcpOptionLabel"] = dhcp_option_policy
            del data["dhcp_option_policy"]
        return data

    def sanitize(self, updates, collate=False, required=None, unwanted=None):
        """Clean up unset keys from a request payload"""
        if required is None:
            required = []
        if unwanted is None:
            unwanted = []
        self.proposed = deepcopy(self.existing)
        self.sent = deepcopy(self.existing)

        if isinstance(self.existing, dict):
            for key in self.existing:
                # Remove References
                if key.endswith("Ref"):
                    del self.proposed[key]
                    del self.sent[key]
                    continue

                # Removed unwanted keys
                elif key in unwanted:
                    del self.proposed[key]
                    del self.sent[key]
                    continue

        if isinstance(updates, dict):
            # Clean up self.sent
            for key in updates:
                # Always retain 'id'
                if key in required:
                    if key in self.existing or updates.get(key) is not None:
                        self.sent[key] = updates.get(key)
                    continue

                # Remove unspecified values
                elif not collate and updates.get(key) is None:
                    if key in self.existing:
                        del self.sent[key]
                    continue

                # Remove identical values
                elif not collate and updates.get(key) == self.existing.get(key):
                    del self.sent[key]
                    continue

                # Add everything else
                if updates.get(key) is not None:
                    self.sent[key] = updates.get(key)

            # Update self.proposed
            self.proposed.update(self.sent)

        elif updates is not None:
            self.sent = updates
            # Update self.proposed
            self.proposed = self.sent

    def delete_keys_from_dict(self, dict_to_sanitize, keys):
        # TODO investigate combine this method above sanitize method
        copy = deepcopy(dict_to_sanitize)
        for (
            k,
            v,
        ) in copy.items():
            if k in keys:
                del dict_to_sanitize[k]
            elif isinstance(v, dict):
                dict_to_sanitize[k] = self.delete_keys_from_dict(v, keys)
            elif isinstance(v, list):
                for index, item in enumerate(v):
                    if isinstance(item, dict):
                        dict_to_sanitize[k][index] = self.delete_keys_from_dict(item, keys)
        return dict_to_sanitize

    def exit_json(self, **kwargs):
        """Custom written method to exit from module."""

        if self.params.get("state") in ("absent", "present", "upload", "restore", "download", "move", "clone"):
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            self.result["method"] = self.method
            self.result["response"] = self.response
            self.result["status"] = self.status
            self.result["url"] = self.url
            self.result["httpapi_logs"] = self.httpapi_logs
            self.result["socket"] = self.module._socket_path

            if self.params.get("state") in ("absent", "present"):
                self.result["sent"] = self.sent
                self.result["proposed"] = self.proposed

                if self.method == "PATCH":
                    self.result["patch_operation"] = self.patch_operation

        self.result["current"] = self.existing

        if self.module._diff and self.result.get("changed") is True:
            self.result["diff"] = dict(
                before=self.previous,
                after=self.existing,
            )

        self.result.update(**kwargs)
        self.module.exit_json(**self.result)

    def fail_json(self, msg, **kwargs):
        """Custom written method to return info on failure."""

        if self.params.get("state") in ("absent", "present"):
            if self.params.get("output_level") in ("debug", "info"):
                self.result["previous"] = self.previous
            # FIXME: Modified header only works for PATCH
            if not self.has_modified and self.previous != self.existing:
                self.result["changed"] = True
        if self.stdout:
            self.result["stdout"] = self.stdout

        # Return the gory details when we need it
        if self.params.get("output_level") == "debug":
            if self.url is not None:
                self.result["method"] = self.method
                self.result["response"] = self.response
                self.result["status"] = self.status
                self.result["url"] = self.url
                self.result["httpapi_logs"] = self.httpapi_logs
                self.result["socket"] = self.module._socket_path

            if self.params.get("state") in ("absent", "present"):
                self.result["sent"] = self.sent
                self.result["proposed"] = self.proposed

                if self.method == "PATCH":
                    self.result["patch_operation"] = self.patch_operation

        self.result["current"] = self.existing

        self.result.update(**kwargs)
        self.module.fail_json(msg=msg, **self.result)

    def check_changed(self):
        """Check if changed by comparing new values from existing"""
        existing = self.existing
        if "password" in existing:
            existing["password"] = self.sent.get("password")

        existing = self.remove_keys_from_dict_when_value_empty(existing)
        self.stdout = json.dumps(existing)

        return not issubset(self.sent, existing)

    def update_service_graph_obj(self, service_graph_obj):
        """update filter with more information"""
        service_graph_obj["serviceGraphRef"] = self.dict_from_ref(service_graph_obj.get("serviceGraphRef"))
        for service_node in service_graph_obj["serviceNodesRelationship"]:
            service_node.get("consumerConnector")["bdRef"] = self.dict_from_ref(service_node.get("consumerConnector").get("bdRef"))
            service_node.get("providerConnector")["bdRef"] = self.dict_from_ref(service_node.get("providerConnector").get("bdRef"))
            service_node["serviceNodeRef"] = self.dict_from_ref(service_node.get("serviceNodeRef"))
        if service_graph_obj.get("serviceGraphContractRelationRef"):
            del service_graph_obj["serviceGraphContractRelationRef"]

    def update_filter_obj(self, contract_obj, filter_obj, filter_type, contract_display_name=None, update_filter_ref=True):
        """update filter with more information"""
        if update_filter_ref:
            filter_obj["filterRef"] = self.dict_from_ref(filter_obj.get("filterRef"))
        if contract_display_name:
            filter_obj["displayName"] = contract_display_name
        else:
            filter_obj["displayName"] = contract_obj.get("displayName")
        filter_obj["filterType"] = filter_type
        filter_obj["contractScope"] = contract_obj.get("scope")
        filter_obj["contractFilterType"] = contract_obj.get("filterType")
        # Conditional statement 'description == ""' is needed to set empty string.
        if contract_obj.get("description") or contract_obj.get("description") == "":
            filter_obj["description"] = contract_obj.get("description")
        # Conditional statement is needed to determine if "prio" exist in contract object.
        # Same reason as described mso_schema_template_contract_filter.py.
        if contract_obj.get("prio"):
            filter_obj["prio"] = contract_obj.get("prio")

    def query_schema(self, schema):
        schema_id = self.lookup_schema(schema)
        schema_path = "schemas/{0}".format(schema_id)
        schema_obj = self.query_obj(schema_path, displayName=schema)
        if not schema_obj:
            self.module.fail_json(msg="Schema '{0}' is not a valid schema name.".format(schema))
        return schema_id, schema_path, schema_obj

    def query_service_node_types(self):
        node_objs = self.query_objs("schemas/service-node-types", key="serviceNodeTypes")
        if not node_objs:
            self.module.fail_json(msg="Service node types do not exist")
        return node_objs

    def lookup_service_node_device(self, site_id, tenant, device_name=None, service_node_type=None):
        if service_node_type is None:
            node_devices = self.query_objs("sites/{0}/aci/tenants/{1}/devices".format(site_id, tenant), key="devices")
        else:
            node_devices = self.query_objs("sites/{0}/aci/tenants/{1}/devices?deviceType={2}".format(site_id, tenant, service_node_type), key="devices")
        if device_name is not None:
            for device in node_devices:
                if device_name == device.get("name"):
                    return device
            self.module.fail_json(msg="Provided device '{0}' of type '{1}' does not exist.".format(device_name, service_node_type))
        return node_devices

    # Workaround function due to inconsistency in attributes REQUEST/RESPONSE API
    # Fix for MSO Error 400: Bad Request: (0)(0)(0)(0)/deploymentImmediacy error.path.missing
    def find_dicts_with_target_key(self, target_dict, target, replace, result=None):
        if result is None:
            result = []

        for key, value in target_dict.items():
            if key == target:
                result.append(target_dict)
            if isinstance(value, dict):
                self.find_dicts_with_target_key(value, target, replace, result)
            if isinstance(value, list):
                for entry in value:
                    if isinstance(entry, dict):
                        self.find_dicts_with_target_key(entry, target, replace, result)

        return result

    # Workaround function due to inconsistency in attributes REQUEST/RESPONSE API
    # Fix for MSO Error 400: Bad Request: (0)(0)(0)(0)/deploymentImmediacy error.path.missing
    def replace_keys_in_dict(self, target, replace, target_dict=None):
        if target_dict is None:
            target_dict = self.existing

        key_list = self.find_dicts_with_target_key(target_dict, target, replace)
        for item in key_list:
            item[replace] = item.get(target)
            del item[target]

    # Workaround function to remove null/None fields returned by API RESPONSE
    def remove_keys_from_dict_when_value_empty(self, target_dict, modified_target=None):
        if modified_target is None:
            modified_target = deepcopy(target_dict)

        for key, value in target_dict.items():
            if value is None:
                del modified_target[key]
            elif isinstance(value, dict):
                self.remove_keys_from_dict_when_value_empty(value, modified_target[key])
            elif isinstance(value, list):
                for entry_index, entry in enumerate(value):
                    if isinstance(entry, dict):
                        self.remove_keys_from_dict_when_value_empty(entry, modified_target[key][entry_index])

        return modified_target

    def validate_schema(self, schema_id):
        return self.request("schemas/{id}/validate".format(id=schema_id), method="GET")
