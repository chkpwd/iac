# -*- coding: utf-8 -*-
# Copyright: (c) 2019, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from . import errors, http


def get(path):
    url = "https://bonsai.sensu.io/api/v1/assets/{0}".format(path)
    resp = http.request("GET", url)

    if resp.status != 200:
        raise errors.BonsaiError(
            "Server returned status {0}".format(resp.status),
        )
    if resp.json is None:
        raise errors.BonsaiError("Server returned invalid JSON document")

    return resp.json


def get_available_asset_versions(namespace, name):
    asset_data = get("{0}/{1}".format(namespace, name))
    try:
        return set(v["version"] for v in asset_data["versions"])
    except (TypeError, KeyError):
        raise errors.BonsaiError(
            "Cannot extract versions from {0}".format(asset_data),
        )


def get_asset_version_builds(namespace, name, version):
    asset = get("{0}/{1}/{2}/release_asset_builds".format(
        namespace, name, version,
    ))
    if "spec" not in asset or "builds" not in asset["spec"]:
        raise errors.BonsaiError("Invalid build spec: {0}".format(asset))
    return asset


def get_asset_parameters(name, version):
    try:
        namespace, asset_name = name.split("/")
    except ValueError:
        raise errors.BonsaiError(
            "Bonsai asset names should be formatted as <namespace>/<name>.",
        )

    available_versions = get_available_asset_versions(namespace, asset_name)
    if version not in available_versions:
        raise errors.BonsaiError(
            "Version {0} is not available. Choose from: {1}.".format(
                version, ", ".join(available_versions),
            ),
        )

    asset_builds = get_asset_version_builds(namespace, asset_name, version)

    return dict(
        labels=asset_builds.get("metadata", {}).get("labels"),
        annotations=asset_builds.get("metadata", {}).get("annotations"),
        builds=asset_builds["spec"]["builds"],
    )
