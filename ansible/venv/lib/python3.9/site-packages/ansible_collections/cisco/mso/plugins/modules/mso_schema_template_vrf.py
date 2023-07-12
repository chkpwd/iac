#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Anvitha Jain (@anvitha-jain) <anvjain@cisco.com>
# Copyright: (c) 2018, Dag Wieers (@dagwieers) <dag@wieers.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_template_vrf
short_description: Manage VRFs in schema templates
description:
- Manage VRFs in schema templates on Cisco ACI Multi-Site.
author:
- Anvitha Jain (@anvitha-jain)
- Dag Wieers (@dagwieers)
options:
  schema:
    description:
    - The name of the schema.
    type: str
    required: true
  template:
    description:
    - The name of the template.
    type: str
    required: true
  vrf:
    description:
    - The name of the VRF to manage.
    type: str
    aliases: [ name ]
  display_name:
    description:
    - The name as displayed on the MSO web interface.
    type: str
  layer3_multicast:
    description:
    - Whether to enable L3 multicast.
    type: bool
  vzany:
    description:
    - Whether to enable vzAny.
    type: bool
  ip_data_plane_learning:
    description:
    - Whether IP data plane learning is enabled or disabled.
    - The APIC defaults to C(enabled) when unset during creation.
    type: str
    choices: [ disabled, enabled ]
  preferred_group:
    description:
    - Whether to enable preferred Endpoint Group.
    - The APIC defaults to C(false) when unset during creation.
    type: bool
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment: cisco.mso.modules
"""

EXAMPLES = r"""
- name: Add a new VRF
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF 1
    state: present
  delegate_to: localhost

- name: Remove an VRF
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF1
    state: absent
  delegate_to: localhost

- name: Query a specific VRFs
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    vrf: VRF1
    state: query
  delegate_to: localhost
  register: query_result

- name: Query all VRFs
  cisco.mso.mso_schema_template_vrf:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema 1
    template: Template 1
    state: query
  delegate_to: localhost
  register: query_result
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        vrf=dict(type="str", aliases=["name"]),  # This parameter is not required for querying all objects
        display_name=dict(type="str"),
        layer3_multicast=dict(type="bool"),
        vzany=dict(type="bool"),
        preferred_group=dict(type="bool"),
        ip_data_plane_learning=dict(type="str", choices=["enabled", "disabled"]),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["vrf"]],
            ["state", "present", ["vrf"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    vrf = module.params.get("vrf")
    display_name = module.params.get("display_name")
    layer3_multicast = module.params.get("layer3_multicast")
    vzany = module.params.get("vzany")
    ip_data_plane_learning = module.params.get("ip_data_plane_learning")
    preferred_group = module.params.get("preferred_group")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = [t.get("name") for t in schema_obj.get("templates")]
    if template not in templates:
        mso.fail_json(msg="Provided template '{0}' does not exist. Existing templates: {1}".format(template, ", ".join(templates)))
    template_idx = templates.index(template)

    # Get ANP
    vrfs = [v.get("name") for v in schema_obj.get("templates")[template_idx]["vrfs"]]

    if vrf is not None and vrf in vrfs:
        vrf_idx = vrfs.index(vrf)
        mso.existing = schema_obj.get("templates")[template_idx]["vrfs"][vrf_idx]

    if state == "query":
        if vrf is None:
            mso.existing = schema_obj.get("templates")[template_idx]["vrfs"]
        elif not mso.existing:
            mso.fail_json(msg="VRF '{vrf}' not found".format(vrf=vrf))
        mso.exit_json()

    vrfs_path = "/templates/{0}/vrfs".format(template)
    vrf_path = "/templates/{0}/vrfs/{1}".format(template, vrf)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=vrf_path))

    elif state == "present":
        if display_name is None and not mso.existing:
            display_name = vrf

        payload = dict(
            name=vrf,
            displayName=display_name,
            l3MCast=layer3_multicast,
            vzAnyEnabled=vzany,
            preferredGroup=preferred_group,
            ipDataPlaneLearning=ip_data_plane_learning,
        )

        mso.sanitize(payload, collate=True)

        if mso.existing:
            # clean contractRef to fix api issue
            for contract in mso.sent.get("vzAnyConsumerContracts"):
                contract["contractRef"] = mso.dict_from_ref(contract.get("contractRef"))
            for contract in mso.sent.get("vzAnyProviderContracts"):
                contract["contractRef"] = mso.dict_from_ref(contract.get("contractRef"))
            ops.append(dict(op="replace", path=vrf_path, value=mso.sent))
        else:
            ops.append(dict(op="add", path=vrfs_path + "/-", value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
