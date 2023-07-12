#!/usr/bin/python
from __future__ import absolute_import, division, print_function

# Copyright: (c) 2022 Fortinet
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

__metaclass__ = type

ANSIBLE_METADATA = {
    "status": ["preview"],
    "supported_by": "community",
    "metadata_version": "1.1",
}

DOCUMENTATION = """
---
module: fortios_system_sdn_connector
short_description: Configure connection to SDN Connector in Fortinet's FortiOS and FortiGate.
description:
    - This module is able to configure a FortiGate or FortiOS (FOS) device by allowing the
      user to set and modify system feature and sdn_connector category.
      Examples include all parameters and values need to be adjusted to datasources before usage.
      Tested with FOS v6.0.0
version_added: "2.0.0"
author:
    - Link Zheng (@chillancezen)
    - Jie Xue (@JieX19)
    - Hongbin Lu (@fgtdev-hblu)
    - Frank Shen (@frankshen01)
    - Miguel Angel Munoz (@mamunozgonzalez)
    - Nicolas Thomas (@thomnico)
notes:
    - Legacy fortiosapi has been deprecated, httpapi is the preferred way to run playbooks

requirements:
    - ansible>=2.9
options:
    access_token:
        description:
            - Token-based authentication.
              Generated from GUI of Fortigate.
        type: str
        required: false
    enable_log:
        description:
            - Enable/Disable logging for task.
        type: bool
        required: false
        default: false
    vdom:
        description:
            - Virtual domain, among those defined previously. A vdom is a
              virtual instance of the FortiGate that can be configured and
              used as a different unit.
        type: str
        default: root
    member_path:
        type: str
        description:
            - Member attribute path to operate on.
            - Delimited by a slash character if there are more than one attribute.
            - Parameter marked with member_path is legitimate for doing member operation.
    member_state:
        type: str
        description:
            - Add or delete a member under specified attribute path.
            - When member_state is specified, the state option is ignored.
        choices:
            - 'present'
            - 'absent'

    state:
        description:
            - Indicates whether to create or remove the object.
        type: str
        required: true
        choices:
            - 'present'
            - 'absent'
    system_sdn_connector:
        description:
            - Configure connection to SDN Connector.
        default: null
        type: dict
        suboptions:
            access_key:
                description:
                    - AWS / ACS access key ID.
                type: str
            alt_resource_ip:
                description:
                    - Enable/disable AWS alternative resource IP.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            api_key:
                description:
                    - IBM cloud API key or service ID API key.
                type: str
            azure_region:
                description:
                    - Azure server region.
                type: str
                choices:
                    - 'global'
                    - 'china'
                    - 'germany'
                    - 'usgov'
                    - 'local'
            client_id:
                description:
                    - Azure client ID (application ID).
                type: str
            client_secret:
                description:
                    - Azure client secret (application key).
                type: str
            compartment_id:
                description:
                    - Compartment ID.
                type: str
            compartment_list:
                description:
                    - Configure OCI compartment list.
                type: list
                elements: dict
                suboptions:
                    compartment_id:
                        description:
                            - OCI compartment ID.
                        required: true
                        type: str
            compute_generation:
                description:
                    - Compute generation for IBM cloud infrastructure.
                type: int
            domain:
                description:
                    - Domain name.
                type: str
            external_account_list:
                description:
                    - Configure AWS external account list.
                type: list
                elements: dict
                suboptions:
                    external_id:
                        description:
                            - AWS external ID.
                        type: str
                    region_list:
                        description:
                            - AWS region name list.
                        type: list
                        elements: dict
                        suboptions:
                            region:
                                description:
                                    - AWS region name.
                                required: true
                                type: str
                    role_arn:
                        description:
                            - AWS role ARN to assume.
                        required: true
                        type: str
            external_ip:
                description:
                    - Configure GCP external IP.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - External IP name.
                        required: true
                        type: str
            forwarding_rule:
                description:
                    - Configure GCP forwarding rule.
                type: list
                elements: dict
                suboptions:
                    rule_name:
                        description:
                            - Forwarding rule name.
                        required: true
                        type: str
                    target:
                        description:
                            - Target instance name.
                        type: str
            gcp_project:
                description:
                    - GCP project name.
                type: str
            gcp_project_list:
                description:
                    - Configure GCP project list.
                type: list
                elements: dict
                suboptions:
                    gcp_zone_list:
                        description:
                            - Configure GCP zone list.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - GCP zone name.
                                required: true
                                type: str
                    id:
                        description:
                            - GCP project ID.
                        required: true
                        type: str
            group_name:
                description:
                    - Full path group name of computers.
                type: str
            ha_status:
                description:
                    - Enable/disable use for FortiGate HA service.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            ibm_region:
                description:
                    - IBM cloud region name.
                type: str
                choices:
                    - 'dallas'
                    - 'washington-dc'
                    - 'london'
                    - 'frankfurt'
                    - 'sydney'
                    - 'tokyo'
                    - 'osaka'
                    - 'toronto'
                    - 'sao-paulo'
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
            ibm_region_gen1:
                description:
                    - IBM cloud compute generation 1 region name.
                type: str
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'germany'
                    - 'great-britain'
                    - 'japan'
                    - 'australia'
            ibm_region_gen2:
                description:
                    - IBM cloud compute generation 2 region name.
                type: str
                choices:
                    - 'us-south'
                    - 'us-east'
                    - 'great-britain'
            key_passwd:
                description:
                    - Private key password.
                type: str
            login_endpoint:
                description:
                    - Azure Stack login endpoint.
                type: str
            name:
                description:
                    - SDN connector name.
                required: true
                type: str
            nic:
                description:
                    - Configure Azure network interface.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - Configure IP configuration.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - IP configuration name.
                                required: true
                                type: str
                            public_ip:
                                description:
                                    - Public IP name.
                                type: str
                            resource_group:
                                description:
                                    - Resource group of Azure public IP.
                                type: str
                    name:
                        description:
                            - Network interface name.
                        required: true
                        type: str
            oci_cert:
                description:
                    - OCI certificate. Source certificate.local.name.
                type: str
            oci_fingerprint:
                description:
                    - OCI pubkey fingerprint.
                type: str
            oci_region:
                description:
                    - OCI server region.
                type: str
                choices:
                    - 'phoenix'
                    - 'ashburn'
                    - 'frankfurt'
                    - 'london'
            oci_region_list:
                description:
                    - Configure OCI region list.
                type: list
                elements: dict
                suboptions:
                    region:
                        description:
                            - OCI region.
                        required: true
                        type: str
            oci_region_type:
                description:
                    - OCI region type.
                type: str
                choices:
                    - 'commercial'
                    - 'government'
            password:
                description:
                    - Password of the remote SDN connector as login credentials.
                type: str
            private_key:
                description:
                    - Private key of GCP service account.
                type: str
            proxy:
                description:
                    - SDN proxy. Source system.sdn-proxy.name.
                type: str
            region:
                description:
                    - AWS / ACS region name.
                type: str
            resource_group:
                description:
                    - Azure resource group.
                type: str
            resource_url:
                description:
                    - Azure Stack resource URL.
                type: str
            route:
                description:
                    - Configure GCP route.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Route name.
                        required: true
                        type: str
            route_table:
                description:
                    - Configure Azure route table.
                type: list
                elements: dict
                suboptions:
                    name:
                        description:
                            - Route table name.
                        required: true
                        type: str
                    resource_group:
                        description:
                            - Resource group of Azure route table.
                        type: str
                    route:
                        description:
                            - Configure Azure route.
                        type: list
                        elements: dict
                        suboptions:
                            name:
                                description:
                                    - Route name.
                                required: true
                                type: str
                            next_hop:
                                description:
                                    - Next hop address.
                                type: str
                    subscription_id:
                        description:
                            - Subscription ID of Azure route table.
                        type: str
            secret_key:
                description:
                    - AWS / ACS secret access key.
                type: str
            secret_token:
                description:
                    - Secret token of Kubernetes service account.
                type: str
            server:
                description:
                    - Server address of the remote SDN connector.
                type: str
            server_ca_cert:
                description:
                    - Trust only those servers whose certificate is directly/indirectly signed by this certificate. Source certificate.remote.name certificate
                      .ca.name.
                type: str
            server_cert:
                description:
                    - Trust servers that contain this certificate only. Source certificate.remote.name.
                type: str
            server_list:
                description:
                    - Server address list of the remote SDN connector.
                type: list
                elements: dict
                suboptions:
                    ip:
                        description:
                            - IPv4 address.
                        required: true
                        type: str
            server_port:
                description:
                    - Port number of the remote SDN connector.
                type: int
            service_account:
                description:
                    - GCP service account email.
                type: str
            status:
                description:
                    - Enable/disable connection to the remote SDN connector.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            subscription_id:
                description:
                    - Azure subscription ID.
                type: str
            tenant_id:
                description:
                    - Tenant ID (directory ID).
                type: str
            type:
                description:
                    - Type of SDN connector.
                type: str
                choices:
                    - 'aci'
                    - 'alicloud'
                    - 'aws'
                    - 'azure'
                    - 'gcp'
                    - 'nsx'
                    - 'nuage'
                    - 'oci'
                    - 'openstack'
                    - 'kubernetes'
                    - 'vmware'
                    - 'sepm'
                    - 'aci-direct'
                    - 'ibm'
                    - 'nutanix'
                    - 'sap'
            update_interval:
                description:
                    - Dynamic object update interval (30 - 3600 sec).
                type: int
            use_metadata_iam:
                description:
                    - Enable/disable use of IAM role from metadata to call API.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            user_id:
                description:
                    - User ID.
                type: str
            username:
                description:
                    - Username of the remote SDN connector as login credentials.
                type: str
            vcenter_password:
                description:
                    - vCenter server password for NSX quarantine.
                type: str
            vcenter_server:
                description:
                    - vCenter server address for NSX quarantine.
                type: str
            vcenter_username:
                description:
                    - vCenter server username for NSX quarantine.
                type: str
            verify_certificate:
                description:
                    - Enable/disable server certificate verification.
                type: str
                choices:
                    - 'disable'
                    - 'enable'
            vpc_id:
                description:
                    - AWS VPC ID.
                type: str
"""

EXAMPLES = """
- hosts: fortigates
  collections:
    - fortinet.fortios
  connection: httpapi
  vars:
   vdom: "root"
   ansible_httpapi_use_ssl: yes
   ansible_httpapi_validate_certs: no
   ansible_httpapi_port: 443
  tasks:
  - name: Configure connection to SDN Connector.
    fortios_system_sdn_connector:
      vdom:  "{{ vdom }}"
      state: "present"
      access_token: "<your_own_value>"
      system_sdn_connector:
        access_key: "<your_own_value>"
        alt_resource_ip: "disable"
        api_key: "<your_own_value>"
        azure_region: "global"
        client_id: "<your_own_value>"
        client_secret: "<your_own_value>"
        compartment_id: "<your_own_value>"
        compartment_list:
         -
            compartment_id: "<your_own_value>"
        compute_generation: "2"
        domain: "<your_own_value>"
        external_account_list:
         -
            external_id: "<your_own_value>"
            region_list:
             -
                region: "<your_own_value>"
            role_arn: "<your_own_value>"
        external_ip:
         -
            name: "default_name_20"
        forwarding_rule:
         -
            rule_name: "<your_own_value>"
            target: "<your_own_value>"
        gcp_project: "<your_own_value>"
        gcp_project_list:
         -
            gcp_zone_list:
             -
                name: "default_name_27"
            id:  "28"
        group_name: "<your_own_value>"
        ha_status: "disable"
        ibm_region: "dallas"
        ibm_region_gen1: "us-south"
        ibm_region_gen2: "us-south"
        key_passwd: "<your_own_value>"
        login_endpoint: "<your_own_value>"
        name: "default_name_36"
        nic:
         -
            ip:
             -
                name: "default_name_39"
                public_ip: "<your_own_value>"
                resource_group: "<your_own_value>"
            name: "default_name_42"
        oci_cert: "<your_own_value> (source certificate.local.name)"
        oci_fingerprint: "<your_own_value>"
        oci_region: "phoenix"
        oci_region_list:
         -
            region: "<your_own_value>"
        oci_region_type: "commercial"
        password: "<your_own_value>"
        private_key: "<your_own_value>"
        proxy: "<your_own_value> (source system.sdn-proxy.name)"
        region: "<your_own_value>"
        resource_group: "<your_own_value>"
        resource_url: "<your_own_value>"
        route:
         -
            name: "default_name_56"
        route_table:
         -
            name: "default_name_58"
            resource_group: "<your_own_value>"
            route:
             -
                name: "default_name_61"
                next_hop: "<your_own_value>"
            subscription_id: "<your_own_value>"
        secret_key: "<your_own_value>"
        secret_token: "<your_own_value>"
        server: "192.168.100.40"
        server_ca_cert: "<your_own_value> (source certificate.remote.name certificate.ca.name)"
        server_cert: "<your_own_value> (source certificate.remote.name)"
        server_list:
         -
            ip: "<your_own_value>"
        server_port: "0"
        service_account: "<your_own_value>"
        status: "disable"
        subscription_id: "<your_own_value>"
        tenant_id: "<your_own_value>"
        type: "aci"
        update_interval: "60"
        use_metadata_iam: "disable"
        user_id: "<your_own_value>"
        username: "<your_own_value>"
        vcenter_password: "<your_own_value>"
        vcenter_server: "<your_own_value>"
        vcenter_username: "<your_own_value>"
        verify_certificate: "disable"
        vpc_id: "<your_own_value>"

"""

RETURN = """
build:
  description: Build number of the fortigate image
  returned: always
  type: str
  sample: '1547'
http_method:
  description: Last method used to provision the content into FortiGate
  returned: always
  type: str
  sample: 'PUT'
http_status:
  description: Last result given by FortiGate on last operation applied
  returned: always
  type: str
  sample: "200"
mkey:
  description: Master key (id) used in the last call to FortiGate
  returned: success
  type: str
  sample: "id"
name:
  description: Name of the table used to fulfill the request
  returned: always
  type: str
  sample: "urlfilter"
path:
  description: Path of the table used to fulfill the request
  returned: always
  type: str
  sample: "webfilter"
revision:
  description: Internal revision number
  returned: always
  type: str
  sample: "17.0.2.10658"
serial:
  description: Serial number of the unit
  returned: always
  type: str
  sample: "FGVMEVYYQT3AB5352"
status:
  description: Indication of the operation's result
  returned: always
  type: str
  sample: "success"
vdom:
  description: Virtual domain used
  returned: always
  type: str
  sample: "root"
version:
  description: Version of the FortiGate
  returned: always
  type: str
  sample: "v5.6.3"

"""
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    FortiOSHandler,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_legacy_fortiosapi,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    schema_to_module_spec,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.fortios import (
    check_schema_versioning,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortimanager.common import (
    FAIL_SOCKET_MSG,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.data_post_processor import (
    remove_invalid_fields,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    is_same_comparison,
)
from ansible_collections.fortinet.fortios.plugins.module_utils.fortios.comparison import (
    serialize,
)


def filter_system_sdn_connector_data(json):
    option_list = [
        "access_key",
        "alt_resource_ip",
        "api_key",
        "azure_region",
        "client_id",
        "client_secret",
        "compartment_id",
        "compartment_list",
        "compute_generation",
        "domain",
        "external_account_list",
        "external_ip",
        "forwarding_rule",
        "gcp_project",
        "gcp_project_list",
        "group_name",
        "ha_status",
        "ibm_region",
        "ibm_region_gen1",
        "ibm_region_gen2",
        "key_passwd",
        "login_endpoint",
        "name",
        "nic",
        "oci_cert",
        "oci_fingerprint",
        "oci_region",
        "oci_region_list",
        "oci_region_type",
        "password",
        "private_key",
        "proxy",
        "region",
        "resource_group",
        "resource_url",
        "route",
        "route_table",
        "secret_key",
        "secret_token",
        "server",
        "server_ca_cert",
        "server_cert",
        "server_list",
        "server_port",
        "service_account",
        "status",
        "subscription_id",
        "tenant_id",
        "type",
        "update_interval",
        "use_metadata_iam",
        "user_id",
        "username",
        "vcenter_password",
        "vcenter_server",
        "vcenter_username",
        "verify_certificate",
        "vpc_id",
    ]

    json = remove_invalid_fields(json)
    dictionary = {}

    for attribute in option_list:
        if attribute in json and json[attribute] is not None:
            dictionary[attribute] = json[attribute]

    return dictionary


def underscore_to_hyphen(data):
    if isinstance(data, list):
        for i, elem in enumerate(data):
            data[i] = underscore_to_hyphen(elem)
    elif isinstance(data, dict):
        new_data = {}
        for k, v in data.items():
            new_data[k.replace("_", "-")] = underscore_to_hyphen(v)
        data = new_data

    return data


def system_sdn_connector(data, fos, check_mode=False):

    vdom = data["vdom"]

    state = data["state"]

    system_sdn_connector_data = data["system_sdn_connector"]
    filtered_data = underscore_to_hyphen(
        filter_system_sdn_connector_data(system_sdn_connector_data)
    )

    # check_mode starts from here
    if check_mode:
        diff = {
            "before": "",
            "after": filtered_data,
        }
        mkey = fos.get_mkey("system", "sdn-connector", filtered_data, vdom=vdom)
        current_data = fos.get("system", "sdn-connector", vdom=vdom, mkey=mkey)
        is_existed = (
            current_data
            and current_data.get("http_status") == 200
            and isinstance(current_data.get("results"), list)
            and len(current_data["results"]) > 0
        )

        # 2. if it exists and the state is 'present' then compare current settings with desired
        if state == "present" or state is True:
            if mkey is None:
                return False, True, filtered_data, diff

            # if mkey exists then compare each other
            # record exits and they're matched or not
            if is_existed:
                is_same = is_same_comparison(
                    serialize(current_data["results"][0]), serialize(filtered_data)
                )
                return (
                    False,
                    not is_same,
                    filtered_data,
                    {"before": current_data["results"][0], "after": filtered_data},
                )

            # record does not exist
            return False, True, filtered_data, diff

        if state == "absent":
            if mkey is None:
                return (
                    False,
                    False,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )

            if is_existed:
                return (
                    False,
                    True,
                    filtered_data,
                    {"before": current_data["results"][0], "after": ""},
                )
            return False, False, filtered_data, {}

        return True, False, {"reason: ": "Must provide state parameter"}, {}

    if state == "present" or state is True:
        return fos.set("system", "sdn-connector", data=filtered_data, vdom=vdom)

    elif state == "absent":
        return fos.delete(
            "system", "sdn-connector", mkey=filtered_data["name"], vdom=vdom
        )
    else:
        fos._module.fail_json(msg="state must be present or absent!")


def is_successful_status(resp):
    return (
        "status" in resp
        and resp["status"] == "success"
        or "http_status" in resp
        and resp["http_status"] == 200
        or "http_method" in resp
        and resp["http_method"] == "DELETE"
        and resp["http_status"] == 404
    )


def fortios_system(data, fos, check_mode):

    fos.do_member_operation("system", "sdn-connector")
    if data["system_sdn_connector"]:
        resp = system_sdn_connector(data, fos, check_mode)
    else:
        fos._module.fail_json(msg="missing task body: %s" % ("system_sdn_connector"))
    if check_mode:
        return resp
    return (
        not is_successful_status(resp),
        is_successful_status(resp)
        and (resp["revision_changed"] if "revision_changed" in resp else True),
        resp,
        {},
    )


versioned_schema = {
    "type": "list",
    "elements": "dict",
    "children": {
        "name": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "required": True,
        },
        "status": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "type": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "aci",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "alicloud",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "aws",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "azure",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "gcp",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "nsx",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "nuage",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "oci",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "openstack",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "kubernetes",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "vmware",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "sepm",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "aci-direct",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "ibm",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "nutanix",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": False,
                        "v6.4.1": False,
                        "v6.4.0": False,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
                {
                    "value": "sap",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": False,
                        "v7.0.8": False,
                        "v7.0.7": False,
                        "v7.0.6": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.1": False,
                        "v6.4.0": False,
                        "v6.2.7": False,
                        "v6.2.5": False,
                        "v6.2.3": False,
                        "v6.2.0": False,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                },
            ],
        },
        "proxy": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": False,
                "v7.2.2": False,
                "v7.2.1": False,
                "v7.2.0": False,
                "v7.0.8": False,
                "v7.0.7": False,
                "v7.0.6": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "use_metadata_iam": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "ha_status": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
            ],
        },
        "verify_certificate": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "disable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
                {
                    "value": "enable",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                    },
                },
            ],
        },
        "server": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "server_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "ip": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                    },
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "server_port": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "integer",
        },
        "username": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "password": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "vcenter_server": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "vcenter_username": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "vcenter_password": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "access_key": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "secret_key": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "region": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "vpc_id": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "alt_resource_ip": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": False,
                "v7.2.1": False,
                "v7.2.0": False,
                "v7.0.8": False,
                "v7.0.7": False,
                "v7.0.6": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {"value": "disable", "revisions": {"v7.4.0": True, "v7.2.4": True}},
                {"value": "enable", "revisions": {"v7.4.0": True, "v7.2.4": True}},
            ],
        },
        "external_account_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "role_arn": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                    "type": "string",
                    "required": True,
                },
                "external_id": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": False,
                        "v7.0.8": True,
                        "v7.0.7": False,
                        "v7.0.6": False,
                        "v7.0.5": False,
                        "v7.0.4": False,
                    },
                    "type": "string",
                },
                "region_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "region": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                            "type": "string",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "tenant_id": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "client_id": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "client_secret": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "subscription_id": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "resource_group": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "login_endpoint": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "resource_url": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "azure_region": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "global",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "china",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "germany",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "usgov",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
                {
                    "value": "local",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            ],
        },
        "nic": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "required": True,
                },
                "ip": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "string",
                            "required": True,
                        },
                        "public_ip": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "string",
                        },
                        "resource_group": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": False,
                                "v6.0.11": False,
                                "v6.0.0": False,
                            },
                            "type": "string",
                        },
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
        },
        "route_table": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "required": True,
                },
                "subscription_id": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": False,
                        "v6.2.0": True,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                    "type": "string",
                },
                "resource_group": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": False,
                        "v6.0.11": False,
                        "v6.0.0": False,
                    },
                    "type": "string",
                },
                "route": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "string",
                            "required": True,
                        },
                        "next_hop": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                                "v7.0.3": True,
                                "v7.0.2": True,
                                "v7.0.1": True,
                                "v7.0.0": True,
                                "v6.4.4": True,
                                "v6.4.1": True,
                                "v6.4.0": True,
                                "v6.2.7": True,
                                "v6.2.5": True,
                                "v6.2.3": True,
                                "v6.2.0": True,
                                "v6.0.5": True,
                                "v6.0.11": True,
                                "v6.0.0": True,
                            },
                            "type": "string",
                        },
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
        },
        "user_id": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "compartment_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "compartment_id": {
                    "revisions": {"v7.4.0": True},
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": False,
                "v7.2.2": False,
                "v7.2.1": False,
                "v7.2.0": False,
                "v7.0.8": False,
                "v7.0.7": False,
                "v7.0.6": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "oci_region_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "region": {
                    "revisions": {"v7.4.0": True},
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": False,
                "v7.2.2": False,
                "v7.2.1": False,
                "v7.2.0": False,
                "v7.0.8": False,
                "v7.0.7": False,
                "v7.0.6": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "oci_region_type": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "commercial",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
                {
                    "value": "government",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                    },
                },
            ],
        },
        "oci_cert": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "external_ip": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
        },
        "route": {
            "type": "list",
            "elements": "dict",
            "children": {
                "name": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.1": True,
                        "v6.4.0": True,
                        "v6.2.7": True,
                        "v6.2.5": True,
                        "v6.2.3": True,
                        "v6.2.0": True,
                        "v6.0.5": True,
                        "v6.0.11": True,
                        "v6.0.0": True,
                    },
                    "type": "string",
                    "required": True,
                }
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
        },
        "gcp_project_list": {
            "type": "list",
            "elements": "dict",
            "children": {
                "id": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                    "type": "string",
                    "required": True,
                },
                "gcp_zone_list": {
                    "type": "list",
                    "elements": "dict",
                    "children": {
                        "name": {
                            "revisions": {
                                "v7.4.0": True,
                                "v7.2.4": True,
                                "v7.2.2": True,
                                "v7.2.1": True,
                                "v7.2.0": True,
                                "v7.0.8": True,
                                "v7.0.7": True,
                                "v7.0.6": True,
                                "v7.0.5": True,
                                "v7.0.4": True,
                            },
                            "type": "string",
                            "required": True,
                        }
                    },
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                    },
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "forwarding_rule": {
            "type": "list",
            "elements": "dict",
            "children": {
                "rule_name": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "string",
                    "required": True,
                },
                "target": {
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": True,
                        "v7.0.2": True,
                    },
                    "type": "string",
                },
            },
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
        },
        "service_account": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "private_key": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "secret_token": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "domain": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "group_name": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "server_cert": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": False,
                "v7.2.1": False,
                "v7.2.0": False,
                "v7.0.8": False,
                "v7.0.7": False,
                "v7.0.6": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "server_ca_cert": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": False,
                "v7.2.1": False,
                "v7.2.0": False,
                "v7.0.8": False,
                "v7.0.7": False,
                "v7.0.6": False,
                "v7.0.5": False,
                "v7.0.4": False,
                "v7.0.3": False,
                "v7.0.2": False,
                "v7.0.1": False,
                "v7.0.0": False,
                "v6.4.4": False,
                "v6.4.1": False,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "api_key": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
        },
        "compute_generation": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "integer",
        },
        "ibm_region": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": False,
                "v6.4.0": True,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {
                    "value": "dallas",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "washington-dc",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "london",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "frankfurt",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "sydney",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "tokyo",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "osaka",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "toronto",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "sao-paulo",
                    "revisions": {
                        "v7.4.0": True,
                        "v7.2.4": True,
                        "v7.2.2": True,
                        "v7.2.1": True,
                        "v7.2.0": True,
                        "v7.0.8": True,
                        "v7.0.7": True,
                        "v7.0.6": True,
                        "v7.0.5": True,
                        "v7.0.4": True,
                        "v7.0.3": False,
                        "v7.0.2": False,
                        "v7.0.1": False,
                        "v7.0.0": False,
                        "v6.4.4": False,
                        "v6.4.0": False,
                    },
                },
                {
                    "value": "us-south",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                    },
                },
                {
                    "value": "us-east",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                    },
                },
                {
                    "value": "germany",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                    },
                },
                {
                    "value": "great-britain",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                    },
                },
                {
                    "value": "japan",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                    },
                },
                {
                    "value": "australia",
                    "revisions": {
                        "v7.0.3": True,
                        "v7.0.2": True,
                        "v7.0.1": True,
                        "v7.0.0": True,
                        "v6.4.4": True,
                        "v6.4.0": True,
                    },
                },
            ],
        },
        "update_interval": {
            "revisions": {
                "v7.4.0": True,
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "integer",
        },
        "compartment_id": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "oci_region": {
            "revisions": {
                "v7.2.4": True,
                "v7.2.2": True,
                "v7.2.1": True,
                "v7.2.0": True,
                "v7.0.8": True,
                "v7.0.7": True,
                "v7.0.6": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
            "options": [
                {
                    "value": "phoenix",
                    "revisions": {"v6.0.5": True, "v6.0.11": True, "v6.0.0": True},
                },
                {
                    "value": "ashburn",
                    "revisions": {"v6.0.5": True, "v6.0.11": True, "v6.0.0": True},
                },
                {
                    "value": "frankfurt",
                    "revisions": {"v6.0.5": True, "v6.0.11": True, "v6.0.0": True},
                },
                {
                    "value": "london",
                    "revisions": {"v6.0.5": True, "v6.0.11": True, "v6.0.0": True},
                },
            ],
        },
        "oci_fingerprint": {
            "revisions": {
                "v7.2.0": True,
                "v7.0.5": True,
                "v7.0.4": True,
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "gcp_project": {
            "revisions": {
                "v7.0.3": True,
                "v7.0.2": True,
                "v7.0.1": True,
                "v7.0.0": True,
                "v6.4.4": True,
                "v6.4.1": True,
                "v6.4.0": True,
                "v6.2.7": True,
                "v6.2.5": True,
                "v6.2.3": True,
                "v6.2.0": True,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
        "ibm_region_gen1": {
            "revisions": {
                "v6.4.1": True,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {"value": "us-south", "revisions": {"v6.4.1": True}},
                {"value": "us-east", "revisions": {"v6.4.1": True}},
                {"value": "germany", "revisions": {"v6.4.1": True}},
                {"value": "great-britain", "revisions": {"v6.4.1": True}},
                {"value": "japan", "revisions": {"v6.4.1": True}},
                {"value": "australia", "revisions": {"v6.4.1": True}},
            ],
        },
        "ibm_region_gen2": {
            "revisions": {
                "v6.4.1": True,
                "v6.4.0": False,
                "v6.2.7": False,
                "v6.2.5": False,
                "v6.2.3": False,
                "v6.2.0": False,
                "v6.0.5": False,
                "v6.0.11": False,
                "v6.0.0": False,
            },
            "type": "string",
            "options": [
                {"value": "us-south", "revisions": {"v6.4.1": True}},
                {"value": "us-east", "revisions": {"v6.4.1": True}},
                {"value": "great-britain", "revisions": {"v6.4.1": True}},
            ],
        },
        "key_passwd": {
            "revisions": {
                "v6.2.3": True,
                "v6.2.0": False,
                "v6.0.5": True,
                "v6.0.11": True,
                "v6.0.0": True,
            },
            "type": "string",
        },
    },
    "revisions": {
        "v7.4.0": True,
        "v7.2.4": True,
        "v7.2.2": True,
        "v7.2.1": True,
        "v7.2.0": True,
        "v7.0.8": True,
        "v7.0.7": True,
        "v7.0.6": True,
        "v7.0.5": True,
        "v7.0.4": True,
        "v7.0.3": True,
        "v7.0.2": True,
        "v7.0.1": True,
        "v7.0.0": True,
        "v6.4.4": True,
        "v6.4.1": True,
        "v6.4.0": True,
        "v6.2.7": True,
        "v6.2.5": True,
        "v6.2.3": True,
        "v6.2.0": True,
        "v6.0.5": True,
        "v6.0.11": True,
        "v6.0.0": True,
    },
}


def main():
    module_spec = schema_to_module_spec(versioned_schema)
    mkeyname = "name"
    fields = {
        "access_token": {"required": False, "type": "str", "no_log": True},
        "enable_log": {"required": False, "type": "bool", "default": False},
        "vdom": {"required": False, "type": "str", "default": "root"},
        "member_path": {"required": False, "type": "str"},
        "member_state": {
            "type": "str",
            "required": False,
            "choices": ["present", "absent"],
        },
        "state": {"required": True, "type": "str", "choices": ["present", "absent"]},
        "system_sdn_connector": {
            "required": False,
            "type": "dict",
            "default": None,
            "options": {},
        },
    }
    for attribute_name in module_spec["options"]:
        fields["system_sdn_connector"]["options"][attribute_name] = module_spec[
            "options"
        ][attribute_name]
        if mkeyname and mkeyname == attribute_name:
            fields["system_sdn_connector"]["options"][attribute_name]["required"] = True

    module = AnsibleModule(argument_spec=fields, supports_check_mode=True)
    check_legacy_fortiosapi(module)

    versions_check_result = None
    if module._socket_path:
        connection = Connection(module._socket_path)
        if "access_token" in module.params:
            connection.set_option("access_token", module.params["access_token"])

        if "enable_log" in module.params:
            connection.set_option("enable_log", module.params["enable_log"])
        else:
            connection.set_option("enable_log", False)
        fos = FortiOSHandler(connection, module, mkeyname)
        versions_check_result = check_schema_versioning(
            fos, versioned_schema, "system_sdn_connector"
        )

        is_error, has_changed, result, diff = fortios_system(
            module.params, fos, module.check_mode
        )

    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    if versions_check_result and versions_check_result["matched"] is False:
        module.warn(
            "Ansible has detected version mismatch between FortOS system and your playbook, see more details by specifying option -vvv"
        )

    if not is_error:
        if versions_check_result and versions_check_result["matched"] is False:
            module.exit_json(
                changed=has_changed,
                version_check_warning=versions_check_result,
                meta=result,
                diff=diff,
            )
        else:
            module.exit_json(changed=has_changed, meta=result, diff=diff)
    else:
        if versions_check_result and versions_check_result["matched"] is False:
            module.fail_json(
                msg="Error in repo",
                version_check_warning=versions_check_result,
                meta=result,
            )
        else:
            module.fail_json(msg="Error in repo", meta=result)


if __name__ == "__main__":
    main()
