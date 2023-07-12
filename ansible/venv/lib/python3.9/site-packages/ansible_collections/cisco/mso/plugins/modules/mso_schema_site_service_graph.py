#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2022, Shreyas Srish (@shrsr) <ssrish@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "community"}

DOCUMENTATION = r"""
---
module: mso_schema_site_service_graph
short_description: Manage Service Graph in schema sites
description:
- Manage Service Graph in schema sites on Cisco ACI Multi-Site.
- This module is only supported in MSO/NDO version 3.3 and above.
author:
- Shreyas Srish (@shrsr)
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
  site:
    description:
    - The name of the site.
    type: str
    required: true
  tenant:
    description:
    - The name of the tenant.
    type: str
  service_graph:
    description:
    - The name of the Service Graph to manage.
    type: str
    aliases: [ name ]
  devices:
    description:
    - A list of devices to be associated with the Service Graph.
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the device
        required: true
        type: str
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
- name: Add a Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    tenant: tenant1
    devices:
      - name: ansible_test_firewall
      - name: ansible_test_adc
      - name: ansible_test_other
    state: present
  delegate_to: localhost

- name: Remove a Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    state: absent
  delegate_to: localhost

- name: Query a specific Service Graph
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    service_graph: SG1
    site: site1
    state: query
  delegate_to: localhost

- name: Query all Service Graphs
  cisco.mso.mso_schema_site_service_graph_node:
    host: mso_host
    username: admin
    password: SomeSecretPassword
    schema: Schema1
    template: Template1
    site: site1
    state: query
  delegate_to: localhost
"""

RETURN = r"""
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.mso.plugins.module_utils.mso import MSOModule, mso_argument_spec, mso_service_graph_node_device_spec


def main():
    argument_spec = mso_argument_spec()
    argument_spec.update(
        schema=dict(type="str", required=True),
        template=dict(type="str", required=True),
        service_graph=dict(type="str", aliases=["name"]),
        tenant=dict(type="str"),
        site=dict(type="str", required=True),
        devices=dict(type="list", elements="dict", options=mso_service_graph_node_device_spec()),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["service_graph"]],
            ["state", "present", ["service_graph", "devices"]],
        ],
    )

    schema = module.params.get("schema")
    template = module.params.get("template").replace(" ", "")
    service_graph = module.params.get("service_graph")
    devices = module.params.get("devices")
    site = module.params.get("site")
    tenant = module.params.get("tenant")
    state = module.params.get("state")

    mso = MSOModule(module)

    # Get schema
    schema_id, schema_path, schema_obj = mso.query_schema(schema)

    # Get template
    templates = schema_obj.get("templates")
    template_names = [t.get("name") for t in templates]
    if template not in template_names:
        mso.fail_json(
            msg="Provided template '{template}' does not exist. Existing templates: {templates}".format(template=template, templates=", ".join(template_names))
        )
    template_idx = template_names.index(template)

    # Get site
    site_id = mso.lookup_site(site)

    # Get site_idx
    if not schema_obj.get("sites"):
        mso.fail_json(msg="No site associated with template '{0}'. Associate the site with the template using mso_schema_site.".format(template))
    sites = [(s.get("siteId"), s.get("templateName")) for s in schema_obj.get("sites")]
    if (site_id, template) not in sites:
        mso.fail_json(msg="Provided site-template association '{0}-{1}' does not exist.".format(site, template))

    # Schema-access uses indexes
    site_idx = sites.index((site_id, template))
    # Path-based access uses site_id-template
    site_template = "{0}-{1}".format(site_id, template)

    mso.existing = {}
    service_graph_idx = None

    # Get Service Graph
    service_graph_ref = mso.service_graph_ref(schema_id=schema_id, template=template, service_graph=service_graph)
    service_graph_refs = [f.get("serviceGraphRef") for f in schema_obj.get("sites")[site_idx]["serviceGraphs"]]
    if service_graph is not None and service_graph_ref in service_graph_refs:
        service_graph_idx = service_graph_refs.index(service_graph_ref)
        mso.existing = schema_obj.get("sites")[site_idx]["serviceGraphs"][service_graph_idx]

    if state == "query":
        if service_graph is None:
            mso.existing = schema_obj.get("sites")[site_idx]["serviceGraphs"]
        elif service_graph is not None and service_graph_idx is None:
            mso.fail_json(msg="Service Graph '{service_graph}' not found".format(service_graph=service_graph))
        mso.exit_json()

    service_graphs_path = "/sites/{0}/serviceGraphs/-".format(site_template)
    service_graph_path = "/sites/{0}/serviceGraphs/{1}".format(site_template, service_graph)
    ops = []

    mso.previous = mso.existing
    if state == "absent":
        if mso.existing:
            mso.sent = mso.existing = {}
            ops.append(dict(op="remove", path=service_graph_path))

    elif state == "present":
        devices_payload = []
        service_graphs = templates[template_idx]["serviceGraphs"]
        for graph in service_graphs:
            if graph.get("name") == service_graph:
                service_node_types_from_template = graph["serviceNodes"]
        user_number_devices = len(devices)
        number_of_nodes_in_template = len(service_node_types_from_template)
        if user_number_devices != number_of_nodes_in_template:
            mso.fail_json(
                msg="Service Graph '{0}' has '{1}' service node type(s) but '{2}' service node(s) were given for the service graph".format(
                    service_graph, number_of_nodes_in_template, user_number_devices
                )
            )

        if devices is not None:
            service_node_type_names_from_template = [type.get("name") for type in service_node_types_from_template]
            for index, device in enumerate(devices):
                template_node_type = service_node_type_names_from_template[index]
                apic_type = "OTHERS"
                if template_node_type == "firewall":
                    apic_type = "FW"
                elif template_node_type == "load-balancer":
                    apic_type = "ADC"
                query_device_data = mso.lookup_service_node_device(site_id, tenant, device.get("name"), apic_type)
                devices_payload.append(
                    dict(
                        device=dict(
                            dn=query_device_data.get("dn"),
                            funcTyp=query_device_data.get("funcType"),
                        ),
                        serviceNodeRef=dict(
                            serviceNodeName=template_node_type,
                            serviceGraphName=service_graph,
                            templateName=template,
                            schemaId=schema_id,
                        ),
                    ),
                )

        payload = dict(
            serviceGraphRef=dict(
                serviceGraphName=service_graph,
                templateName=template,
                schemaId=schema_id,
            ),
            serviceNodes=devices_payload,
        )

        mso.sanitize(payload, collate=True)

        if not mso.existing:
            ops.append(dict(op="add", path=service_graphs_path, value=payload))
        else:
            ops.append(dict(op="replace", path=service_graph_path, value=mso.sent))

        mso.existing = mso.proposed

    if not module.check_mode:
        mso.request(schema_path, method="PATCH", data=ops)

    mso.exit_json()


if __name__ == "__main__":
    main()
