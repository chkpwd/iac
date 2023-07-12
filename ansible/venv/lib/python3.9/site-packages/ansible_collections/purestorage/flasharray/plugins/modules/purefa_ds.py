#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2018, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_ds
version_added: '1.0.0'
short_description: Configure FlashArray Directory Service
description:
- Set or erase configuration for the directory service. There is no facility
  to SSL certificates at this time. Use the FlashArray GUI for this
  additional configuration work.
- To modify an existing directory service configuration you must first delete
  an exisitng configuration and then recreate with new settings.
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  state:
    type: str
    description:
    - Create or delete directory service configuration
    default: present
    choices: [ absent, present ]
  enable:
    description:
    - Whether to enable or disable directory service support.
    default: false
    type: bool
  dstype:
    description:
    - The type of directory service to work on
    choices: [ management, data ]
    type: str
    default: management
  uri:
    type: list
    elements: str
    description:
    - A list of up to 30 URIs of the directory servers. Each URI must include
      the scheme ldap:// or ldaps:// (for LDAP over SSL), a hostname, and a
      domain name or IP address. For example, ldap://ad.company.com configures
      the directory service with the hostname "ad" in the domain "company.com"
      while specifying the unencrypted LDAP protocol.
  base_dn:
    type: str
    description:
    - Sets the base of the Distinguished Name (DN) of the directory service
      groups. The base should consist of only Domain Components (DCs). The
      base_dn will populate with a default value when a URI is entered by
      parsing domain components from the URI. The base DN should specify DC=
      for each domain component and multiple DCs should be separated by commas.
  bind_password:
    type: str
    description:
    - Sets the password of the bind_user user name account.
  force_bind_password:
    type: bool
    default: true
    description:
    - Will force the bind password to be reset even if the bind user password
      is unchanged.
    - If set to I(false) and I(bind_user) is unchanged the password will not
      be reset.
    version_added: 1.14.0
  bind_user:
    type: str
    description:
    - Sets the user name that can be used to bind to and query the directory.
    - For Active Directory, enter the username - often referred to as
      sAMAccountName or User Logon Name - of the account that is used to
      perform directory lookups.
    - For OpenLDAP, enter the full DN of the user.
  group_base:
    type: str
    description:
    - Specifies where the configured groups are located in the directory
      tree. This field consists of Organizational Units (OUs) that combine
      with the base DN attribute and the configured group CNs to complete
      the full Distinguished Name of the groups. The group base should
      specify OU= for each OU and multiple OUs should be separated by commas.
      The order of OUs is important and should get larger in scope from left
      to right. Each OU should not exceed 64 characters in length.
    - Not Supported from Purity 5.2.0 or higher.
      Use I(purestorage.flasharray.purefa_dsrole) module.
  ro_group:
    type: str
    description:
    - Sets the common Name (CN) of the configured directory service group
      containing users with read-only privileges on the FlashArray. This
      name should be just the Common Name of the group without the CN=
      specifier. Common Names should not exceed 64 characters in length.
    - Not Supported from Purity 5.2.0 or higher.
      Use I(purestorage.flasharray.purefa_dsrole) module.
  sa_group:
    type: str
    description:
    - Sets the common Name (CN) of the configured directory service group
      containing administrators with storage-related privileges on the
      FlashArray. This name should be just the Common Name of the group
      without the CN= specifier. Common Names should not exceed 64
      characters in length.
    - Not Supported from Purity 5.2.0 or higher.
      Use I(purestorage.flasharray.purefa_dsrole) module.
  aa_group:
    type: str
    description:
    - Sets the common Name (CN) of the directory service group containing
      administrators with full privileges when managing the FlashArray.
      The name should be just the Common Name of the group without the
      CN= specifier. Common Names should not exceed 64 characters in length.
    - Not Supported from Purity 5.2.0 or higher.
      Use I(purestorage.flasharray.purefa_dsrole) module.
  user_login:
    type: str
    description:
    - User login attribute in the structure of the configured LDAP servers.
      Typically the attribute field that holds the users unique login name.
      Default value is I(sAMAccountName) for Active Directory or I(uid)
      for all other directory services
    - Supported from Purity 6.0 or higher.
  user_object:
    type: str
    description:
    - Value of the object class for a management LDAP user.
      Defaults to I(User) for Active Directory servers, I(posixAccount) or
      I(shadowAccount) for OpenLDAP servers dependent on the group type
      of the server, or person for all other directory servers.
    - Supported from Purity 6.0 or higher.
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Delete existing directory service
  purestorage.flasharray.purefa_ds:
    state: absent
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create directory service (disabled) - Pre-5.2.0
  purestorage.flasharray.purefa_ds:
    uri: "ldap://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    group_base: "OU=Pure-Admin"
    ro_group: PureReadOnly
    sa_group: PureStorage
    aa_group: PureAdmin
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create directory service (disabled) - 5.2.0 or higher
  purestorage.flasharray.purefa_ds:
    dstype: management
    uri: "ldap://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Enable existing directory service
  purestorage.flasharray.purefa_ds:
    enable: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Disable existing directory service
  purestorage.flasharray.purefa_ds:
    enable: false
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create directory service (enabled) - Pre-5.2.0
  purestorage.flasharray.purefa_ds:
    enable: true
    uri: "ldap://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    group_base: "OU=Pure-Admin"
    ro_group: PureReadOnly
    sa_group: PureStorage
    aa_group: PureAdmin
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Create directory service (enabled) - 5.2.0 or higher
  purestorage.flasharray.purefa_ds:
    enable: true
    dstype: management
    uri: "ldap://lab.purestorage.com"
    base_dn: "DC=lab,DC=purestorage,DC=com"
    bind_user: Administrator
    bind_password: password
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    get_system,
    purefa_argument_spec,
)


DS_ROLE_REQUIRED_API_VERSION = "1.16"
FAFILES_API_VERSION = "2.2"


def disable_ds(module, array):
    """Disable Directory Service"""
    changed = True
    if not module.check_mode:
        try:
            array.disable_directory_service()
        except Exception:
            module.fail_json(msg="Disable Directory Service failed")
    module.exit_json(changed=changed)


def enable_ds(module, array):
    """Enable Directory Service"""
    changed = False
    api_version = array._list_available_rest_versions()
    if DS_ROLE_REQUIRED_API_VERSION in api_version:
        try:
            roles = array.list_directory_service_roles()
            enough_roles = False
            for role in range(0, len(roles)):
                if roles[role]["group_base"]:
                    enough_roles = True
            if enough_roles:
                changed = True
                if not module.check_mode:
                    array.enable_directory_service()
            else:
                module.fail_json(
                    msg="Cannot enable directory service - please create a directory service role"
                )
        except Exception:
            module.fail_json(msg="Enable Directory Service failed: Check Configuration")
    else:
        try:
            changed = True
            if not module.check_mode:
                array.enable_directory_service()
        except Exception:
            module.fail_json(msg="Enable Directory Service failed: Check Configuration")
    module.exit_json(changed=changed)


def delete_ds(module, array):
    """Delete Directory Service"""
    changed = True
    if not module.check_mode:
        try:
            api_version = array._list_available_rest_versions()
            array.set_directory_service(enabled=False)
            if DS_ROLE_REQUIRED_API_VERSION in api_version:
                array.set_directory_service(
                    uri=[""], base_dn="", bind_user="", bind_password="", certificate=""
                )
            else:
                array.set_directory_service(
                    uri=[""],
                    base_dn="",
                    group_base="",
                    bind_user="",
                    bind_password="",
                    readonly_group="",
                    storage_admin_group="",
                    array_admin_group="",
                    certificate="",
                )
        except Exception:
            module.fail_json(msg="Delete Directory Service failed")
    module.exit_json(changed=changed)


def delete_ds_v6(module, array):
    """Delete Directory Service"""
    changed = True
    if module.params["dstype"] == "management":
        management = flasharray.DirectoryServiceManagement(
            user_login_attribute="", user_object_class=""
        )
        directory_service = flasharray.DirectoryService(
            uris=[""],
            base_dn="",
            bind_user="",
            bind_password="",
            enabled=False,
            services=module.params["dstype"],
            management=management,
        )
    else:
        directory_service = flasharray.DirectoryService(
            uris=[""],
            base_dn="",
            bind_user="",
            bind_password="",
            enabled=False,
            services=module.params["dstype"],
        )
    if not module.check_mode:
        res = array.patch_directory_services(
            names=[module.params["dstype"]], directory_service=directory_service
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Delete {0} Directory Service failed. Error message: {1}".format(
                    module.params["dstype"], res.errors[0].message
                )
            )
    module.exit_json(changed=changed)


def create_ds(module, array):
    """Create Directory Service"""
    changed = False
    if None in (
        module.params["bind_password"],
        module.params["bind_user"],
        module.params["base_dn"],
        module.params["uri"],
    ):
        module.fail_json(
            msg="Parameters 'bind_password', 'bind_user', 'base_dn' and 'uri' are all required"
        )
    api_version = array._list_available_rest_versions()
    if DS_ROLE_REQUIRED_API_VERSION in api_version:
        try:
            changed = True
            if not module.check_mode:
                array.set_directory_service(
                    uri=module.params["uri"],
                    base_dn=module.params["base_dn"],
                    bind_user=module.params["bind_user"],
                    bind_password=module.params["bind_password"],
                )
                roles = array.list_directory_service_roles()
                enough_roles = False
                for role in range(0, len(roles)):
                    if roles[role]["group_base"]:
                        enough_roles = True
                if enough_roles:
                    array.set_directory_service(enabled=module.params["enable"])
                else:
                    module.fail_json(
                        msg="Cannot enable directory service - please create a directory service role"
                    )
        except Exception:
            module.fail_json(msg="Create Directory Service failed: Check configuration")
    else:
        groups_rule = [
            not module.params["ro_group"],
            not module.params["sa_group"],
            not module.params["aa_group"],
        ]

        if all(groups_rule):
            module.fail_json(msg="At least one group must be configured")
        try:
            changed = True
            if not module.check_mode:
                array.set_directory_service(
                    uri=module.params["uri"],
                    base_dn=module.params["base_dn"],
                    group_base=module.params["group_base"],
                    bind_user=module.params["bind_user"],
                    bind_password=module.params["bind_password"],
                    readonly_group=module.params["ro_group"],
                    storage_admin_group=module.params["sa_group"],
                    array_admin_group=module.params["aa_group"],
                )
                array.set_directory_service(enabled=module.params["enable"])
        except Exception:
            module.fail_json(msg="Create Directory Service failed: Check configuration")
    module.exit_json(changed=changed)


def update_ds_v6(module, array):
    """Update Directory Service"""
    changed = False
    ds_change = False
    password_required = False
    dirserv = list(
        array.get_directory_services(
            filter="name='" + module.params["dstype"] + "'"
        ).items
    )[0]
    current_ds = dirserv
    if module.params["uri"] and current_ds.uris is None:
        password_required = True
    if current_ds.uris != module.params["uri"]:
        uris = module.params["uri"]
        ds_change = True
    else:
        uris = current_ds.uris
    try:
        base_dn = current_ds.base_dn
    except AttributeError:
        base_dn = ""
    try:
        bind_user = current_ds.bind_user
    except AttributeError:
        bind_user = ""
    if module.params["base_dn"] != "" and module.params["base_dn"] != base_dn:
        base_dn = module.params["base_dn"]
        ds_change = True
    if module.params["bind_user"] != "":
        bind_user = module.params["bind_user"]
        if module.params["bind_user"] != bind_user:
            password_required = True
            ds_change = True
        elif module.params["force_bind_password"]:
            password_required = True
            ds_change = True
    if module.params["bind_password"] is not None and password_required:
        bind_password = module.params["bind_password"]
        ds_change = True
    if module.params["enable"] != current_ds.enabled:
        ds_change = True
    if password_required and not module.params["bind_password"]:
        module.fail_json(msg="'bind_password' must be provided for this task")
    if module.params["dstype"] == "management":
        try:
            user_login = current_ds.management.user_login_attribute
        except AttributeError:
            user_login = ""
        try:
            user_object = current_ds.management.user_object_class
        except AttributeError:
            user_object = ""
        if (
            module.params["user_object"] is not None
            and user_object != module.params["user_object"]
        ):
            user_object = module.params["user_object"]
            ds_change = True
        if (
            module.params["user_login"] is not None
            and user_login != module.params["user_login"]
        ):
            user_login = module.params["user_login"]
            ds_change = True
        management = flasharray.DirectoryServiceManagement(
            user_login_attribute=user_login, user_object_class=user_object
        )
        if password_required:
            directory_service = flasharray.DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                bind_password=bind_password,
                enabled=module.params["enable"],
                services=module.params["dstype"],
                management=management,
            )
        else:
            directory_service = flasharray.DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                enabled=module.params["enable"],
                services=module.params["dstype"],
                management=management,
            )
    else:
        if password_required:
            directory_service = flasharray.DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                bind_password=bind_password,
                enabled=module.params["enable"],
                services=module.params["dstype"],
            )
        else:
            directory_service = flasharray.DirectoryService(
                uris=uris,
                base_dn=base_dn,
                bind_user=bind_user,
                enabled=module.params["enable"],
                services=module.params["dstype"],
            )
    if ds_change:
        changed = True
        if not module.check_mode:
            res = array.patch_directory_services(
                names=[module.params["dstype"]], directory_service=directory_service
            )
            if res.status_code != 200:
                module.fail_json(
                    msg="{0} Directory Service failed. Error message: {1}".format(
                        module.params["dstype"].capitalize(), res.errors[0].message
                    )
                )
    module.exit_json(changed=changed)


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            uri=dict(type="list", elements="str"),
            state=dict(type="str", default="present", choices=["absent", "present"]),
            enable=dict(type="bool", default=False),
            force_bind_password=dict(type="bool", default=True, no_log=True),
            bind_password=dict(type="str", no_log=True),
            bind_user=dict(type="str"),
            base_dn=dict(type="str"),
            group_base=dict(type="str"),
            user_login=dict(type="str"),
            user_object=dict(type="str"),
            ro_group=dict(type="str"),
            sa_group=dict(type="str"),
            aa_group=dict(type="str"),
            dstype=dict(
                type="str", default="management", choices=["management", "data"]
            ),
        )
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    array = get_system(module)
    api_version = array._list_available_rest_versions()

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required to for this module")

    if FAFILES_API_VERSION in api_version:
        arrayv6 = get_array(module)

    if module.params["dstype"] == "data":
        if FAFILES_API_VERSION in api_version:
            if len(list(arrayv6.get_directory_services().items)) == 1:
                module.warn("FA-Files is not enabled  - ignoring")
                module.exit_json(changed=False)
        else:
            module.fail_json(
                msg="'data' directory service requires Purity//FA 6.0.0 or higher"
            )

    state = module.params["state"]
    ds_exists = False
    if FAFILES_API_VERSION in api_version:
        dirserv = list(
            arrayv6.get_directory_services(
                filter="name='" + module.params["dstype"] + "'"
            ).items
        )[0]
        if state == "absent" and dirserv.uris != []:
            delete_ds_v6(module, arrayv6)
        else:
            update_ds_v6(module, arrayv6)
    else:
        dirserv = array.get_directory_service()
        ds_enabled = dirserv["enabled"]
        if dirserv["base_dn"]:
            ds_exists = True

        if state == "absent" and ds_exists:
            delete_ds(module, array)
        elif ds_exists and module.params["enable"] and ds_enabled:
            module.warn(
                "To update an existing directory service configuration in Purity//FA 5.x, please delete and recreate"
            )
            module.exit_json(changed=False)
        elif ds_exists and not module.params["enable"] and ds_enabled:
            disable_ds(module, array)
        elif ds_exists and module.params["enable"] and not ds_enabled:
            enable_ds(module, array)
        elif not ds_exists and state == "present":
            create_ds(module, array)
        else:
            module.exit_json(changed=False)

    module.exit_json(changed=False)


if __name__ == "__main__":
    main()
