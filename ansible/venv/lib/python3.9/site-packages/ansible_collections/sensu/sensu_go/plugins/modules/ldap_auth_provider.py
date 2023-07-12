#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2020, XLAB Steampunk <steampunk@xlab.si>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["stableinterface"],
    "supported_by": "certified",
}

DOCUMENTATION = """
module: ldap_auth_provider
author:
  - Aljaz Kosir (@aljazkosir)
  - Manca Bizjak (@mancabizjak)
  - Miha Dolinar (@mdolin)
  - Tadej Borovsak (@tadeboro)

short_description: Manage Sensu LDAP authentication provider

description:
  - Create, update or delete a Sensu Go LDAP authentication provider.
  - For more information, refer to the Sensu Go documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/control-access/ldap-auth/).

version_added: 1.10.0

extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state

options:
  servers:
    description:
      - An array of LDAP servers for your directory.
      - Required if I(state) is C(present).
    type: list
    elements: dict
    suboptions:
      host:
        description:
          - LDAP server IP address.
        required: true
        type: str
      port:
        description:
          - LDAP server port.
        type: int
      insecure:
        description:
          - Skips SSL certificate verification when set to true.
        type: bool
        default: false
      security:
        description:
          - Encryption type to be used for the connection to the LDAP server.
        type: str
        choices: [ insecure, tls, starttls ]
        default: tls
      trusted_ca_file:
        description:
          - Path to an alternative CA bundle file.
        type: str
      client_cert_file:
        description:
          - Path to the certificate that should be sent to the server if requested.
        type: str
      client_key_file:
        description:
          - Path to the key file associated with the client_cert_file.
          - Required if I(client_cert_file) is present.
        type: str
      binding:
        description:
          - The LDAP account that performs user and group lookups.
          - If your sever supports anonymous binding, you can omit the user_dn or password
            attributes to query the directory without credentials.
        type: dict
        suboptions:
          user_dn:
            description:
             - The LDAP account that performs user and group lookups.
             -  If your sever supports anonymous binding, you can omit this attribute.
            type: str
            required: true
          password:
            description:
              - Password for the user_dn account.
              - If your sever supports anonymous binding, you can omit this attribute.
            type: str
            required: true
      group_search:
        description:
         - Search configuration for groups.
        type: dict
        suboptions:
          base_dn:
            description:
              - Which part of the directory tree to search.
            required: true
            type: str
          attribute:
            description:
              - Used for comparing result entries.
            type: str
            default: member
          name_attribute:
            description:
              - Represents the attribute to use as the entry name.
            type: str
            default: cn
          object_class:
            description:
              - Identifies the class of objects returned in the search result.
            type: str
            default: groupOfNames
      user_search:
        description:
          - Search configuration for users.
        type: dict
        suboptions:
          base_dn:
            description:
              - Which part of the directory tree to search.
            required: true
            type: str
          attribute:
            description:
              - Used for comparing result entries.
            type: str
            default: uid
          name_attribute:
            description:
              - Represents the attribute to use as the entry name.
            type: str
            default: cn
          object_class:
            description:
              - Identifies the class of objects returned in the search result.
            type: str
            default: person
  groups_prefix:
    description:
      - The prefix added to all LDAP groups.
    type: str
  username_prefix:
    description:
      - The prefix added to all LDAP usernames.
    type: str

seealso:
  - module: sensu.sensu_go.auth_provider_info
  - module: sensu.sensu_go.ad_auth_provider
  - module: sensu.sensu_go.oidc_auth_provider
"""

EXAMPLES = """
- name: Create a LDAP auth provider
  sensu.sensu_go.ldap_auth_provider:
    name: openldap
    servers:
      - host: 127.0.0.1
        group_search:
          base_dn: dc=acme,dc=org
        user_search:
          base_dn: dc=acme,dc=org

- name: Delete a LDAP auth provider
  sensu.sensu_go.ldap_auth_provider:
    name: openldap
    state: absent
"""

RETURN = """
object:
  description: Object representing Sensu LDAP authentication provider.
  returned: success
  type: dict
  sample:
    metadata:
      name: 'openldap'
    servers:
      host: '127.0.0.1'
      port: '636'
      insecure: 'False'
      security: 'tls'
      trusted_ca_file: '/path/to/trusted-certificate-authorities.pem'
      client_cert_file: '/path/to/ssl/cert.pem'
      client_key_file: '/path/to/ssl/key.pem'
      binding:
        user_dn: 'cn=binder,dc=acme,dc=org'
      group_search:
        base_dn: 'dc=acme,dc=org'
        attribute: 'member'
        name_attribute': 'cn'
        object_class: 'groupOfNames'
      user_search:
        base_dn: 'dc=acme,dc=org'
        attribute: 'uid'
        name_attribute: 'cn'
        object_class: 'person'
    groups_prefix: 'ldap'
    username_prefix: 'ldap'
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "authentication/v2"


def remove_item(result):
    if result:
        for server in result["servers"]:
            if server["binding"] and "password" in server["binding"]:
                del server["binding"]["password"]

    return result


def _filter(payload):
    # Remove keys with None values from dict
    return dict((k, v) for k, v in payload.items() if v is not None)


def do_differ(current, desired):
    if utils.do_differ_v1(current, desired, "servers"):
        return True

    if len(current["spec"]["servers"]) != len(desired["spec"]["servers"]):
        return True

    for c, d in zip(current["spec"]["servers"], desired["spec"]["servers"]):
        if utils.do_differ(c, _filter(d)):
            return True

    return False


def main():
    required_if = [("state", "present", ["servers"])]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec(
                "auth",
                "name",
                "state",
            ),
            servers=dict(
                type="list",
                elements="dict",
                options=dict(
                    host=dict(
                        type="str",
                        required=True,
                    ),
                    port=dict(
                        type="int",
                    ),
                    insecure=dict(
                        type="bool",
                        default=False,
                    ),
                    security=dict(
                        type="str",
                        choices=["insecure", "tls", "starttls"],
                        default="tls",
                    ),
                    trusted_ca_file=dict(
                        type="str",
                    ),
                    client_cert_file=dict(
                        type="str",
                    ),
                    client_key_file=dict(
                        type="str",
                    ),
                    binding=dict(
                        type="dict",
                        options=dict(
                            user_dn=dict(
                                type="str",
                                required=True,
                            ),
                            password=dict(
                                type="str",
                                no_log=True,
                                required=True,
                            ),
                        ),
                    ),
                    group_search=dict(
                        type="dict",
                        options=dict(
                            base_dn=dict(
                                type="str",
                                required=True,
                            ),
                            attribute=dict(
                                type="str",
                                default="member",
                            ),
                            name_attribute=dict(
                                type="str",
                                default="cn",
                            ),
                            object_class=dict(type="str", default="groupOfNames"),
                        ),
                    ),
                    user_search=dict(
                        type="dict",
                        options=dict(
                            base_dn=dict(
                                type="str",
                                required=True,
                            ),
                            attribute=dict(
                                type="str",
                                default="uid",
                            ),
                            name_attribute=dict(
                                type="str",
                                default="cn",
                            ),
                            object_class=dict(
                                type="str",
                                default="person",
                            ),
                        ),
                    ),
                ),
            ),
            groups_prefix=dict(
                type="str",
            ),
            username_prefix=dict(
                type="str",
            ),
        ),
    )

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, None, "authproviders", module.params["name"]
    )

    payload = dict(
        type="ldap",
        api_version=API_VERSION,
        metadata=dict(name=module.params["name"]),
        spec=arguments.get_spec_payload(
            module.params, "servers", "groups_prefix", "username_prefix"
        ),
    )

    try:
        changed, ldap_provider = utils.sync_v1(
            module.params["state"], client, path, payload, module.check_mode, do_differ
        )
        module.exit_json(changed=changed, object=remove_item(ldap_provider))
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
