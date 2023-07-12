# -*- coding: utf-8 -*-
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

try:
    from ansible.module_utils.compat import version
except ImportError:
    from distutils import version

from . import errors, http


class Client:
    BAD_VERSION = version.StrictVersion("9999.99.99")

    def __init__(self, address, username, password, api_key, verify, ca_path):
        self.address = address.rstrip("/")
        self.username = username
        self.password = password
        self.api_key = api_key
        self.verify = verify
        self.ca_path = ca_path

        self._auth_header = None  # Login when/if required
        self._version = None  # Set version only if the consumer needs it

    @property
    def auth_header(self):
        if not self._auth_header:
            self._auth_header = self._login()
        return self._auth_header

    @property
    def version(self):
        if self._version is None:
            resp = self.get("/version")
            if resp.status != 200:
                raise errors.SensuError(
                    "Version API returned status {0}".format(resp.status),
                )
            if resp.json is None:
                raise errors.SensuError(
                    "Version API did not return a valid JSON",
                )
            if "sensu_backend" not in resp.json:
                raise errors.SensuError(
                    "Version API did not return backend version",
                )
            try:
                self._version = version.StrictVersion(
                    resp.json["sensu_backend"].split("#")[0]
                )
            except ValueError:
                # Backend has no version compiled in - we are probably running
                # againts self-compiled version from git.
                self._version = self.BAD_VERSION

        return self._version

    def _login(self):
        if self.api_key:
            return self._api_key_login()
        return self._username_password_login()

    def _api_key_login(self):
        # We cannot validate the API key because there is no API endpoint that
        # we could hit for verification purposes. This means that the error
        # reporting will be a mess but there is not much we can do here.
        return dict(Authorization="Key {0}".format(self.api_key))

    def _username_password_login(self):
        resp = http.request(
            "GET", "{0}/auth".format(self.address), force_basic_auth=True,
            url_username=self.username, url_password=self.password,
            validate_certs=self.verify, ca_path=self.ca_path,
        )

        if resp.status != 200:
            raise errors.SensuError(
                "Authentication call returned status {0}".format(resp.status),
            )

        if resp.json is None:
            raise errors.SensuError(
                "Authentication call did not return a valid JSON",
            )

        if "access_token" not in resp.json:
            raise errors.SensuError(
                "Authentication call did not return access token",
            )

        return dict(
            Authorization="Bearer {0}".format(resp.json["access_token"]),
        )

    def request(self, method, path, payload=None):
        url = self.address + path
        headers = self.auth_header

        response = http.request(
            method, url, payload=payload, headers=headers,
            validate_certs=self.verify, ca_path=self.ca_path,
        )

        if response.status in (401, 403):
            raise errors.SensuError(
                "Authentication problem. Verify your credentials."
            )

        return response

    def get(self, path):
        return self.request("GET", path)

    def put(self, path, payload):
        return self.request("PUT", path, payload)

    def delete(self, path):
        return self.request("DELETE", path)

    def validate_auth_data(self, username, password):
        resp = http.request(
            "GET", "{0}/auth/test".format(self.address),
            force_basic_auth=True, url_username=username,
            url_password=password, validate_certs=self.verify,
            ca_path=self.ca_path,
        )
        if resp.status not in (200, 401):
            raise errors.SensuError(
                "Authentication test returned status {0}".format(resp.status),
            )
        return resp.status == 200
