#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright: (c) 2021, XLAB Steampunk <steampunk@xlab.si>
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
module: etcd_replicator
author:
  - Tadej Borovsak (@tadeboro)
short_description: Manage Sensu Go etcd replicators
description:
  - Create, update or delete Sensu etcd replicator.
  - For more information, refer to the Sensu documentation at
    U(https://docs.sensu.io/sensu-go/latest/operations/deploy-sensu/etcdreplicators/).
version_added: 1.9.0
extends_documentation_fragment:
  - sensu.sensu_go.requirements
  - sensu.sensu_go.auth
  - sensu.sensu_go.name
  - sensu.sensu_go.state
seealso:
  - module: sensu.sensu_go.etcd_replicator_info
options:
  ca_cert:
    description:
      - Path to an the PEM-format CA certificate to use for TLS client authentication.
      - Required if I(insecure) is C(false).
    type: str
  cert:
    description:
      - Path to the PEM-format certificate to use for TLS client authentication. This
        certificate is required for secure client communication.
      - Required if I(insecure) is C(false).
    type: str
  key:
    description:
      - Path to the PEM-format key file associated with the cert to use for TLS client
        authentication. This key and its corresponding certificate are required for
        secure client communication.
      - Required if I(insecure) is C(false).
    type: str
  insecure:
    description:
      - Disable transport security.
      - Only set to C(true) in sandbox and experimental environments.
    type: bool
    default: false
  url:
    description:
      - Destination cluster URLs.
      - Required if I(state) is C(present).
    type: list
    elements: str
  api_version:
    description:
      - Sensu API version of the resource to replicate.
    type: str
  resource:
    description:
      - Name of the resource to replicate.
      - List of all resources is available at
        U(https://docs.sensu.io/sensu-go/latest/operations/control-access/rbac/#resources).
      - Required if I(state) is C(present).
    type: str
  namespace:
    description:
      - Namespace to constrain replication to.
      - If you do not include namespace, all namespaces for a given resource are
        replicated.
    type: str
  replication_interval:
    description:
      - Interval at which the resource will be replicated. In seconds.
    type: int
"""

EXAMPLES = """
- name: Create a minimal replicator
  sensu.sensu_go.etcd_replicator:
    name: cluster_role_replicator
    ca_cert: /etc/sensu/certs/ca.pem
    cert: /etc/sensu/certs/cert.pem
    key: /etc/sensu/certs/key.pem
    url: https://sensu.alpha.example.com:2379
    resource: ClusterRole

- name: Create an insecure minimal replicator
  sensu.sensu_go.etcd_replicator:
    name: role_replicator
    insecure: true
    url:
      - https://sensu.beta.example.com:2379
      - https://sensu.gamma.example.com:2379
    resource: Role

- name: Create a replicator with all parameters set
  sensu.sensu_go.etcd_replicator:
    name: role_binding_replicator
    ca_cert: /etc/sensu/certs/ca.pem
    cert: /etc/sensu/certs/cert.pem
    key: /etc/sensu/certs/key.pem
    insecure: false
    url: https://127.0.0.1:2379
    api_version: core/v2
    resource: RoleBinding
    namespace: default
    replication_interval_seconds: 30

- name: Delete a replicator
  sensu.sensu_go.etcd_replicator:
    name: my_replicator
    state: absent
"""

RETURN = """
object:
  description: Object representing Sensu etcd replicator.
  returned: success
  type: dict
  sample:
    metadata:
      created_by: admin
      name: cluster-role-replicator
    api_version: core/v2
    ca_cert: /etc/sensu/certs/ca.pem
    cert: /etc/sensu/certs/cert.pem
    insecure: false
    key: /etc/sensu/certs/key.pem
    namespace: ""
    replication_interval_seconds: 30
    resource: ClusterRole
    url: https://sensu.alpha.example.com:2379
"""

from ansible.module_utils.basic import AnsibleModule

from ..module_utils import arguments, errors, utils

API_GROUP = "enterprise"
API_VERSION = "federation/v1"


def main():
    required_if = [
        ("state", "present", ["url", "resource"]),
    ]
    module = AnsibleModule(
        required_if=required_if,
        supports_check_mode=True,
        argument_spec=dict(
            arguments.get_spec("auth", "name", "state"),
            ca_cert=dict(type="str"),
            cert=dict(type="str"),
            key=dict(type="str", no_log=False),
            insecure=dict(type="bool", default=False),
            url=dict(type="list", elements="str"),
            api_version=dict(type="str"),
            resource=dict(type="str"),
            namespace=dict(type="str"),
            replication_interval=dict(type="int"),
        ),
    )

    # This complex condition cannot be expressed using built-in checks.
    if module.params["state"] == "present" and module.params["insecure"] is False:
        missing = []
        for key in ("ca_cert", "cert", "key"):
            if not module.params[key]:
                missing.append(key)
        if missing:
            msg = "insecure is False but all of the following are missing: {0}".format(
                ", ".join(missing)
            )
            module.fail_json(msg=msg)

    client = arguments.get_sensu_client(module.params["auth"])
    path = utils.build_url_path(
        API_GROUP, API_VERSION, None, "etcd-replicators", module.params["name"],
    )

    spec = arguments.get_spec_payload(
        module.params, "ca_cert", "cert", "key", "insecure", "api_version",
        "resource", "namespace",
    )
    # We renamed the replication interval a bit.
    if module.params["replication_interval"] is not None:
        spec["replication_interval_seconds"] = module.params["replication_interval"]
    # We accept a list of urls that we need to convert here
    if module.params["url"]:
        spec["url"] = ",".join(module.params["url"])

    payload = dict(
        type="EtcdReplicator",
        api_version=API_VERSION,
        metadata=dict(name=module.params["name"]),
        spec=spec,
    )
    try:
        changed, replicator = utils.sync_v1(
            module.params["state"], client, path, payload, module.check_mode,
        )
        module.exit_json(changed=changed, object=replicator)
    except errors.Error as e:
        module.fail_json(msg=str(e))


if __name__ == "__main__":
    main()
