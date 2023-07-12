#!/usr/bin/env python

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import argparse
import gzip
import pathlib
import shutil
import subprocess
import sys

from urllib import request
from xml.etree import ElementTree

import yaml


BASE_REPO_URL = "https://packagecloud.io/sensu/stable/el/8/x86_64/"
FILENAME_TEMPLATE = "sensu-go-agent_{0}.{1}.{2}.{3}_en-US.{arch}.msi"
DOWNLOAD_URL_TEMPLATE = (
    "https://s3-us-west-2.amazonaws.com/sensu.io/sensu-go/{0}.{1}.{2}/" +
    FILENAME_TEMPLATE
)
MINIMAL_VERSION = (5, 20, 0)


class ArgParser(argparse.ArgumentParser):
    """An argument parser that displays help on error."""

    def error(self, message):
        sys.stderr.write("error: {0}\n".format(message))
        self.print_help()
        sys.exit(2)

    def add_subparsers(self, **kwargs):
        # Workaround for http://bugs.python.org/issue9253
        subparsers = super(ArgParser, self).add_subparsers()
        subparsers.required = True
        subparsers.dest = "command"
        return subparsers


def _fetch_available_versions():
    available_versions = set()

    response = request.urlopen(BASE_REPO_URL + "repodata/repomd.xml", timeout=30)
    root = ElementTree.parse(response).getroot()
    for data in root.iter("{http://linux.duke.edu/metadata/repo}data"):
        if data.get("type") == "primary":
            break
    else:
        return available_versions

    location = next(data.iter("{http://linux.duke.edu/metadata/repo}location"))
    path = location.attrib["href"]

    response = request.urlopen(BASE_REPO_URL + path, timeout=30)
    root = ElementTree.fromstring(gzip.decompress(response.read()))
    for package in root.iter("{http://linux.duke.edu/metadata/common}package"):
        name = next(package.iter("{http://linux.duke.edu/metadata/common}name"))
        if name.text != "sensu-go-agent":
            continue

        version = next(package.iter("{http://linux.duke.edu/metadata/common}version"))
        version_tuple = tuple(int(c) for c in version.get("ver").split("."))
        if version_tuple < MINIMAL_VERSION:
            continue

        available_versions.add(version_tuple + (int(version.get("rel")), ))

    return available_versions


def _load_versions_from_vars(vars):
    return set(
        (tuple(int(c) for c in item["version"].split(".")) + (item["build"],))
        for item in vars["_msi_lookup"].values()
    )


def _sync_versions(vars, available_versions, cache_dir):
    new_vars = dict(vars, _msi_lookup={})

    old_msis = vars["_msi_lookup"]
    new_msis = new_vars["_msi_lookup"]

    cache = pathlib.Path(cache_dir)

    for version in sorted(available_versions):
        version_str = ".".join(map(str, version[:3]))

        if version_str in old_msis:
            # Happy path: we already have this version sorted
            new_msis[version_str] = old_msis[version_str]
            continue

        # Sad path: we need to download packages and extract product codes
        product_codes = {}
        for arch in ("x86", "x64"):
            url = DOWNLOAD_URL_TEMPLATE.format(*version, arch=arch)
            filename = FILENAME_TEMPLATE.format(*version, arch=arch)
            file = cache / filename

            if not file.is_file():
                print("Downloading " + filename)
                with open(file, "wb") as fp:
                    response = request.urlopen(url)
                    shutil.copyfileobj(response, fp)
            else:
                print("Reusing " + filename)

            process = subprocess.run(
                ("msiinfo", "export", str(file), "Property"), capture_output=True,
                check=True
            )
            for line in process.stdout.splitlines():
                field, value = line.split(b"\t")
                if field == b"ProductCode":
                    product_codes[arch] = value.decode("ascii")

        new_msis[version_str] = dict(
            version=version_str, build=version[-1], product_codes=product_codes
        )

    new_msis["latest"] = new_msis[version_str]

    return new_vars


def _load_windows_vars_file(filename):
    with open(filename, "r") as fd:
        return yaml.safe_load(fd)


def _save_windows_vars_file(filename, vars):
    with open(filename, "w") as fd:
        yaml.safe_dump(vars, fd)


def _check(args):
    vars_data = _load_windows_vars_file(args.vars)
    current = _load_versions_from_vars(vars_data)
    available = _fetch_available_versions()

    missing = available - current
    obsolete = current - available

    if missing:
        print("The following versions are missing: {0}".format(
            ", ".join(".".join(map(str, v)) for v in missing)
        ))
    if obsolete:
        print("The following versions are obsolete: {0}".format(
            ", ".join(".".join(map(str, v)) for v in obsolete)
        ))

    return len(missing) + len(obsolete)


def _update(args):
    vars_data = _load_windows_vars_file(args.vars)
    current = _load_versions_from_vars(vars_data)
    available = _fetch_available_versions()

    if current == available:
        return 0

    new_vars_data = _sync_versions(vars_data, available, args.cache)
    _save_windows_vars_file(args.vars, new_vars_data)

    return 0


def main():
    parser = ArgParser(
        description="Windows agent version updater",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    subparsers = parser.add_subparsers()

    check = subparsers.add_parser("check", help="Check for version updates")
    check.add_argument("vars", help="Variable file with Windows lookup table")
    check.set_defaults(func=_check)

    update = subparsers.add_parser("update", help="Update lookup table")
    update.add_argument("vars", help="Variable file with Windows lookup table")
    update.add_argument(
        "--cache", help="Directory used for caching downloads", default="/tmp"
    )
    update.set_defaults(func=_update)

    args = parser.parse_args()

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
