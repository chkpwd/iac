#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2022, René Moser <mail@renemoser.net>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


DOCUMENTATION = """
---
module: instance
short_description: Manages server instances on Vultr.
description:
  - Manage server instances on Vultr.
version_added: "1.1.0"
author:
  - "René Moser (@resmo)"
options:
  label:
    description:
      - Name of the instance.
    required: true
    aliases: [ name ]
    type: str
  hostname:
    description:
      - The hostname to assign to this instance.
    type: str
  os:
    description:
      - The operating system name.
      - Mutually exclusive with I(image) and I(app).
    type: str
  app:
    description:
      - The app deploy name of Vultr OneClick apps.
      - Mutually exclusive with I(image) and I(os).
    type: str
  image:
    description:
      - The image deploy name of Vultr Marketplace apps.
      - Mutually exclusive with I(os) and I(app).
    type: str
  firewall_group:
    description:
      - The firewall group description to assign this instance to.
    type: str
  plan:
    description:
      - The plan name to use for the instance.
      - Required if the instance does not yet exist.
    type: str
  activation_email:
    description:
      - Whether to send an activation email when the instance is ready or not.
      - Only considered on creation.
    type: bool
    default: false
  backups:
    description:
      - Whether to enable automatic backups or not.
    type: bool
  ddos_protection:
    description:
      - Whether to enable ddos_protection or not.
    type: bool
  enable_ipv6:
    description:
      - Whether to enable IPv6 or not.
    type: bool
  tags:
    description:
      - Tags for the instance.
    type: list
    elements: str
  user_data:
    description:
      - User data to be passed to the instance.
    type: str
  startup_script:
    description:
      - Name or ID of the startup script to execute on boot.
      - Only considered while creating the instance.
    type: str
  ssh_keys:
    description:
      - List of SSH key names passed to the instance on creation.
    type: list
    elements: str
  snapshot:
    description:
      - Description or ID of the snapshot.
      - Only considered while creating the instance.
    type: str
    version_added: "1.7.0"
  reserved_ipv4:
    description:
      - IP address of the floating IP to use as the main IP of this instance.
      - Only considered on creation.
    type: str
  region:
    description:
      - Region the instance is deployed into.
    type: str
    required: true
  vpcs:
    description:
      - A list of VPCs identified by their description to be assigned to the instance.
    type: list
    elements: str
    version_added: "1.5.0"
  state:
    description:
      - State of the instance.
      - The state I(reinstalled) was added in version 1.8.0.
    default: present
    choices: [ present, absent, started, stopped, restarted, reinstalled ]
    type: str
extends_documentation_fragment:
  - vultr.cloud.vultr_v2
"""

EXAMPLES = """
---
- name: Create an instance using OS
  vultr.cloud.instance:
    label: my web server
    hostname: my-hostname
    user_data: |
      #cloud-config
      packages:
        - nginx
    firewall_group: my firewall group
    plan: vc2-1c-2gb
    ddos_protection: true
    backups: true
    enable_ipv6: true
    ssh_keys:
      - my ssh key
    vpcs:
      - my vpc description
    tags:
      - web
      - project-genesis
    region: ams
    os: Debian 11 x64 (bullseye)

- name: Deploy an instance of a marketplace app
  vultr.cloud.instance:
    label: git-server
    hostname: git
    firewall_group: my firewall group
    plan: vc2-1c-2gb
    ddos_protection: true
    backups: true
    enable_ipv6: true
    region: ams
    image: Gitea on Ubuntu 20.04

- name: Stop an existing instance
  vultr.cloud.instance:
    label: my web server
    region: ams
    state: stopped

- name: Start an existing instance
  vultr.cloud.instance:
    label: my web server
    region: ams
    state: started

- name: Reinstall an instance
  vultr.cloud.instance:
    label: my web server
    region: ams
    state: reinstalled

- name: Delete an instance
  vultr.cloud.instance:
    label: my web server
    region: ams
    state: absent
"""

RETURN = """
---
vultr_api:
  description: Response from Vultr API with a few additions/modification.
  returned: success
  type: dict
  contains:
    api_timeout:
      description: Timeout used for the API requests.
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests.
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests.
      returned: success
      type: str
      sample: "https://api.vultr.com/v2"
vultr_instance:
  description: Response from Vultr API.
  returned: success
  type: dict
  contains:
    id:
      description: ID of the instance.
      returned: success
      type: str
      sample: cb676a46-66fd-4dfb-b839-443f2e6c0b60
    v6_main_ip:
      description: IPv6 of the instance.
      returned: success
      type: str
      sample: ""
    v6_network:
      description: IPv6 network of the instance.
      returned: success
      type: str
      sample: ""
    v6_network_size:
      description: IPv6 network size of the instance.
      returned: success
      type: int
      sample: 0
    main_ip:
      description: IPv4 of the instance.
      returned: success
      type: str
      sample: 95.179.189.95
    netmask_v4:
      description: Netmask IPv4 of the instance.
      returned: success
      type: str
      sample: 255.255.254.0
    hostname:
      description: Hostname of the instance.
      returned: success
      type: str
      sample: vultr.guest
    internal_ip:
      description: Internal IP of the instance.
      returned: success
      type: str
      sample: ""
    gateway_v4:
      description: Gateway IPv4.
      returned: success
      type: str
      sample: 95.179.188.1
    kvm:
      description: KVM of the instance.
      returned: success
      type: str
      sample: "https://my.vultr.com/subs/vps/novnc/api.php?data=..."
    disk:
      description: Disk size of the instance.
      returned: success
      type: int
      sample: 25
    allowed_bandwidth:
      description: Allowed bandwidth of the instance.
      returned: success
      type: int
      sample: 1000
    vcpu_count:
      description: vCPUs of the instance.
      returned: success
      type: int
      sample: 1
    firewall_group_id:
      description: Firewall group ID of the instance.
      returned: success
      type: str
      sample: ""
    plan:
      description: Plan of the instance.
      returned: success
      type: str
      sample: vc2-1c-1gb
    image_id:
      description: Image ID of the instance.
      returned: success
      type: str
      sample: ""
    os_id:
      description: OS ID of the instance.
      returned: success
      type: int
      sample: 186
    app_id:
      description: App ID of the instance.
      returned: success
      type: int
      sample: 37
    date_created:
      description: Date when the instance was created.
      returned: success
      type: str
      sample: "2020-10-10T01:56:20+00:00"
    label:
      description: Label of the instance.
      returned: success
      type: str
      sample: my instance
    region:
      description: Region the instance was deployed into.
      returned: success
      type: str
      sample: ews
    status:
      description: Status about the deployment of the instance.
      returned: success
      type: str
      sample: active
    server_status:
      description: Server status of the instance.
      returned: success
      type: str
      sample: installingbooting
    power_status:
      description: Power status of the instance.
      returned: success
      type: str
      sample: running
    ram:
      description: RAM in MB of the instance.
      returned: success
      type: int
      sample: 1024
    os:
      description: OS of the instance.
      returned: success
      type: str
      sample: Application
    tags:
      description: Tags of the instance.
      returned: success
      type: list
      sample: [ my-tag ]
    features:
      description: Features of the instance.
      returned: success
      type: list
      sample: [ ddos_protection, ipv6, auto_backups ]
    user_data:
      description: Base64 encoded user data (cloud init) of the instance.
      returned: success
      type: str
      sample: I2Nsb3VkLWNvbmZpZwpwYWNrYWdlczoKICAtIGh0b3AK
    backups:
      description: Whether backups are enabled or disabled.
      returned: success
      type: str
      sample: enabled
      version_added: "1.3.0"
    ddos_protection:
      description: Whether DDOS protections is enabled or not.
      returned: success
      type: bool
      sample: true
      version_added: "1.3.0"
    enable_ipv6:
      description: Whether IPv6 is enabled or not.
      returned: success
      type: bool
      sample: true
      version_added: "1.3.0"
    vpcs:
      description: List of VPCs attached.
      returned: success
      type: list
      version_added: "1.5.0"
      contains:
        id:
          description: ID of the VPC.
          returned: success
          type: str
          sample: 5536d2a4-66fd-4dfb-b839-7672fd5bc116
        description:
          description: Description of the VPC.
          returned: success
          type: str
          sample: my vpc
        ip_address:
          description: IP assigned from the VPC.
          returned: success
          type: str
          sample: "192.168.23.3"
        mac_address:
          description: MAC address of the network interface.
          returned: success
          type: str
          sample: "5a:01:04:3d:5e:72"
"""

import base64

from ansible.module_utils.basic import AnsibleModule

from ..module_utils.vultr_v2 import AnsibleVultr, vultr_argument_spec


class AnsibleVultrInstance(AnsibleVultr):
    def get_ssh_key_ids(self):
        ssh_key_names = list(self.module.params["ssh_keys"])
        ssh_keys = self.query_list(path="/ssh-keys", result_key="ssh_keys")

        ssh_key_ids = list()
        for ssh_key in ssh_keys:
            if ssh_key["name"] in ssh_key_names:
                ssh_key_ids.append(ssh_key["id"])
                ssh_key_names.remove(ssh_key["name"])

        if ssh_key_names:
            self.module.fail_json(msg="SSH key names not found: %s" % ", ".join(ssh_key_names))

        return ssh_key_ids

    def get_vpc_ids(self):
        vpc_names = list(self.module.params["vpcs"])
        vpcs = self.query_list(path="/vpcs", result_key="vpcs")

        vpc_ids = list()
        for vpc in vpcs:
            if vpc["description"] in vpc_names:
                vpc_ids.append(vpc["id"])
                vpc_names.remove(vpc["description"])

        if vpc_names:
            self.module.fail_json(msg="VPCs not found: %s" % ", ".join(vpc_names))

        return vpc_ids

    def get_instance_vpcs(self, resource):
        path = "/instances/%s/vpcs" % resource["id"]
        vpcs = self.query_list(path=path, result_key="vpcs")

        # Workaround to get the description field into the list
        result = list()
        for vpc in vpcs:
            vpc_detail = self.query_by_id(resource_id=vpc["id"], path="/vpcs", result_key="vpc")
            vpc["description"] = vpc_detail["description"]
            result.append(vpc)
        return result

    def get_firewall_group(self):
        return self.query_filter_list_by_name(
            key_name="description",
            param_key="firewall_group",
            path="/firewalls",
            result_key="firewall_groups",
            fail_not_found=True,
        )

    def get_snapshot(self):
        return self.query_filter_list_by_name(
            key_name="description",
            param_key="snapshot",
            path="/snapshots",
            result_key="snapshots",
            fail_not_found=True,
        )

    def get_startup_script(self):
        return self.query_filter_list_by_name(
            key_name="name",
            param_key="startup_script",
            path="/startup-scripts",
            result_key="startup_scripts",
            fail_not_found=True,
        )

    def get_os(self):
        return self.query_filter_list_by_name(
            key_name="name",
            param_key="os",
            path="/os",
            result_key="os",
            fail_not_found=True,
        )

    def get_app(self):
        return self.query_filter_list_by_name(
            key_name="deploy_name",
            param_key="app",
            path="/applications",
            result_key="applications",
            fail_not_found=True,
            query_params={"type": "one-click"},
        )

    def get_image(self):
        return self.query_filter_list_by_name(
            key_name="deploy_name",
            param_key="image",
            path="/applications",
            result_key="applications",
            fail_not_found=True,
            query_params={"type": "marketplace"},
        )

    def get_user_data(self, resource):
        res = self.api_query(
            path="%s/%s/%s" % (self.resource_path, resource[self.resource_key_id], "user-data"),
        )
        if res:
            return str(res.get("user_data", dict()).get("data"))
        return ""

    def transform_resource(self, resource):
        if not resource:
            return resource

        features = resource.get("features", list())
        resource["backups"] = "enabled" if "auto_backups" in features else "disabled"
        resource["enable_ipv6"] = "ipv6" in features
        resource["ddos_protection"] = "ddos_protection" in features
        resource["vpcs"] = self.get_instance_vpcs(resource=resource)

        return resource

    def get_detach_vpcs_ids(self, resource):
        detach_vpc_ids = []
        for vpc in resource.get("vpcs", list()):
            if vpc["id"] not in list(self.module.params["attach_vpc"]):
                detach_vpc_ids.append(vpc["id"])
        return detach_vpc_ids

    def configure(self):
        if self.module.params["state"] != "absent":
            if self.module.params["startup_script"] is not None:
                self.module.params["script_id"] = self.get_startup_script()["id"]

            if self.module.params["snapshot"] is not None:
                self.module.params["snapshot_id"] = self.get_snapshot()["id"]

            if self.module.params["firewall_group"] is not None:
                self.module.params["firewall_group_id"] = self.get_firewall_group()["id"]

            if self.module.params["os"] is not None:
                self.module.params["os_id"] = self.get_os()["id"]

            if self.module.params["app"] is not None:
                self.module.params["app_id"] = self.get_app()["id"]

            if self.module.params["image"] is not None:
                self.module.params["image_id"] = self.get_image()["image_id"]

            if self.module.params["user_data"] is not None:
                self.module.params["user_data"] = base64.b64encode(self.module.params["user_data"].encode())

            if self.module.params["ssh_keys"] is not None:
                # sshkey_id ist a list of ids
                self.module.params["sshkey_id"] = self.get_ssh_key_ids()

            if self.module.params["backups"] is not None:
                self.module.params["backups"] = "enabled" if self.module.params["backups"] else "disabled"

            if self.module.params["vpcs"] is not None:
                # attach_vpc is a list of ids used while creating
                self.module.params["attach_vpc"] = self.get_vpc_ids()

    def handle_power_status(self, resource, state, action, power_status, force=False, wait_for_state=True):
        if state == self.module.params["state"] and (resource["power_status"] != power_status or force):
            self.result["changed"] = True
            if not self.module.check_mode:
                resource = self.wait_for_state(resource=resource, key="server_status", states=["none", "locked"], cmp="!=")
                self.api_query(
                    path="%s/%s/%s" % (self.resource_path, resource[self.resource_key_id], action),
                    method="POST",
                )
                if wait_for_state:
                    resource = self.wait_for_state(resource=resource, key="power_status", states=[power_status])
        return resource

    def create(self):
        param_keys = ("os", "image", "app", "snapshot")
        if not any(self.module.params.get(x) is not None for x in param_keys):
            self.module.fail_json(msg="missing required arguements, one of the following required: %s" % ", ".join(param_keys))
        return super(AnsibleVultrInstance, self).create()

    def update(self, resource):
        user_data = self.get_user_data(resource=resource)
        resource["user_data"] = user_data.encode()

        if self.module.params["vpcs"] is not None:
            resource["attach_vpc"] = list()
            for vpc in list(resource["vpcs"]):
                resource["attach_vpc"].append(vpc["id"])

            # detach_vpc is a list of ids to be detached
            resource["detach_vpc"] = list()
            self.module.params["detach_vpc"] = self.get_detach_vpcs_ids(resource=resource)

        return super(AnsibleVultrInstance, self).update(resource=resource)

    def create_or_update(self):
        resource = super(AnsibleVultrInstance, self).create_or_update()
        if resource:
            resource = self.wait_for_state(resource=resource, key="status", states=["active"])
            resource = self.wait_for_state(resource=resource, key="server_status", states=["none", "locked"], cmp="!=")

            # Hanlde power status
            resource = self.handle_power_status(resource=resource, state="stopped", action="halt", power_status="stopped")
            resource = self.handle_power_status(resource=resource, state="started", action="start", power_status="running")
            resource = self.handle_power_status(resource=resource, state="restarted", action="reboot", power_status="running", force=True)
            resource = self.handle_power_status(
                resource=resource,
                state="reinstalled",
                action="reinstall",
                power_status="running",
                force=True,
                wait_for_state=False,
            )

        return resource

    def transform_result(self, resource):
        if resource:
            resource["user_data"] = self.get_user_data(resource=resource)
        return resource

    def absent(self):
        resource = self.query()
        if resource and not self.module.check_mode:
            resource = self.wait_for_state(resource=resource, key="server_status", states=["none", "locked"], cmp="!=")

        return super(AnsibleVultrInstance, self).absent(resource=resource)


def main():
    argument_spec = vultr_argument_spec()
    argument_spec.update(
        dict(
            label=dict(type="str", required=True, aliases=["name"]),
            hostname=dict(type="str"),
            app=dict(type="str"),
            image=dict(type="str"),
            snapshot=dict(type="str"),
            os=dict(type="str"),
            plan=dict(type="str"),
            activation_email=dict(type="bool", default=False),
            ddos_protection=dict(type="bool"),
            backups=dict(type="bool"),
            enable_ipv6=dict(type="bool"),
            tags=dict(type="list", elements="str"),
            vpcs=dict(type="list", elements="str"),
            reserved_ipv4=dict(type="str"),
            firewall_group=dict(type="str"),
            startup_script=dict(type="str"),
            user_data=dict(type="str"),
            ssh_keys=dict(type="list", elements="str", no_log=False),
            region=dict(type="str", required=True),
            state=dict(
                choices=[
                    "present",
                    "absent",
                    "started",
                    "stopped",
                    "restarted",
                    "reinstalled",
                ],
                default="present",
            ),
        )  # type: ignore
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=(("state", "present", ("plan",)),),
        mutually_exclusive=(("os", "app", "image", "snapshot"),),
        supports_check_mode=True,
    )

    vultr = AnsibleVultrInstance(
        module=module,
        namespace="vultr_instance",
        resource_path="/instances",
        ressource_result_key_singular="instance",
        resource_create_param_keys=[
            "label",
            "hostname",
            "plan",
            "app_id",
            "os_id",
            "iso_id",
            "image_id",
            "snapshot_id",
            "script_id",
            "region",
            "enable_ipv6",
            "reserved_ipv4",
            "firewall_group_id",
            "user_data",
            "tags",
            "activation_email",
            "ddos_protection",
            "sshkey_id",
            "backups",
            "attach_vpc",
        ],
        resource_update_param_keys=[
            "plan",
            "tags",
            "firewall_group_id",
            "enable_ipv6",
            "ddos_protection",
            "backups",
            "user_data",
            "attach_vpc",
            "detach_vpc",
        ],
        resource_key_name="label",
    )

    state = module.params.get("state")  # type: ignore
    if state == "absent":
        vultr.absent()
    else:
        vultr.present()


if __name__ == "__main__":
    main()
