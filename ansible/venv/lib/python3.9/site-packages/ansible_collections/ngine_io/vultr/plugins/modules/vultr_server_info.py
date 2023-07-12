#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2018, Yanis Guenane <yanis+ansible@guenane.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vultr_server_info
short_description: Gather information about the Vultr servers available.
description:
  - Gather information about servers available.
version_added: "0.1.0"
author: "Yanis Guenane (@Spredzy)"
extends_documentation_fragment:
- ngine_io.vultr.vultr

'''

EXAMPLES = r'''
- name: Gather Vultr servers information
  ngine_io.vultr.vultr_server_info:
  register: result

- name: Print the gathered information
  debug:
    var: result.vultr_server_info
'''

RETURN = r'''
---
vultr_api:
  description: Response from Vultr API with a few additions/modification
  returned: success
  type: complex
  contains:
    api_account:
      description: Account used in the ini file to select the key
      returned: success
      type: str
      sample: default
    api_timeout:
      description: Timeout used for the API requests
      returned: success
      type: int
      sample: 60
    api_retries:
      description: Amount of max retries for the API requests
      returned: success
      type: int
      sample: 5
    api_retry_max_delay:
      description: Exponential backoff delay in seconds between retries up to this max delay value.
      returned: success
      type: int
      sample: 12
    api_endpoint:
      description: Endpoint used for the API requests
      returned: success
      type: str
      sample: "https://api.vultr.com"
vultr_server_info:
  description: Response from Vultr API
  returned: success
  type: complex
  contains:
    id:
      description: ID of the server
      returned: success
      type: str
      sample: 10194376
    name:
      description: Name (label) of the server
      returned: success
      type: str
      sample: "ansible-test-vm"
    plan:
      description: Plan used for the server
      returned: success
      type: str
      sample: "1024 MB RAM,25 GB SSD,1.00 TB BW"
    allowed_bandwidth_gb:
      description: Allowed bandwidth to use in GB
      returned: success
      type: float
      sample: 1000.5
    auto_backup_enabled:
      description: Whether automatic backups are enabled
      returned: success
      type: bool
      sample: false
    cost_per_month:
      description: Cost per month for the server
      returned: success
      type: float
      sample: 5.00
    current_bandwidth_gb:
      description: Current bandwidth used for the server
      returned: success
      type: int
      sample: 0
    date_created:
      description: Date when the server was created
      returned: success
      type: str
      sample: "2017-08-26 12:47:48"
    default_password:
      description: Password to login as root into the server
      returned: success
      type: str
      sample: "!p3EWYJm$qDWYaFr"
    disk:
      description: Information about the disk
      returned: success
      type: str
      sample: "Virtual 25 GB"
    v4_gateway:
      description: IPv4 gateway
      returned: success
      type: str
      sample: "45.32.232.1"
    internal_ip:
      description: Internal IP
      returned: success
      type: str
      sample: ""
    kvm_url:
      description: URL to the VNC
      returned: success
      type: str
      sample: "https://my.vultr.com/subs/vps/novnc/api.php?data=xyz"
    region:
      description: Region the server was deployed into
      returned: success
      type: str
      sample: "Amsterdam"
    v4_main_ip:
      description: Main IPv4
      returned: success
      type: str
      sample: "45.32.233.154"
    v4_netmask:
      description: Netmask IPv4
      returned: success
      type: str
      sample: "255.255.254.0"
    os:
      description: Operating system used for the server
      returned: success
      type: str
      sample: "CentOS 6 x64"
    firewall_group:
      description: Firewall group the server is assigned to
      returned: success and available
      type: str
      sample: "CentOS 6 x64"
    pending_charges:
      description: Pending charges
      returned: success
      type: float
      sample: 0.01
    power_status:
      description: Power status of the server
      returned: success
      type: str
      sample: "running"
    ram:
      description: Information about the RAM size
      returned: success
      type: str
      sample: "1024 MB"
    server_state:
      description: State about the server
      returned: success
      type: str
      sample: "ok"
    status:
      description: Status about the deployment of the server
      returned: success
      type: str
      sample: "active"
    tag:
      description: TBD
      returned: success
      type: str
      sample: ""
    v6_main_ip:
      description: Main IPv6
      returned: success
      type: str
      sample: ""
    v6_network:
      description: Network IPv6
      returned: success
      type: str
      sample: ""
    v6_network_size:
      description:  Network size IPv6
      returned: success
      type: str
      sample: ""
    v6_networks:
      description: Networks IPv6
      returned: success
      type: list
      sample: []
    vcpu_count:
      description: Virtual CPU count
      returned: success
      type: int
      sample: 1
'''

from ansible.module_utils.basic import AnsibleModule
from ..module_utils.vultr import (
    Vultr,
    vultr_argument_spec,
)


class AnsibleVultrServerInfo(Vultr):

    def __init__(self, module):
        super(AnsibleVultrServerInfo, self).__init__(module, "vultr_server_info")

        self.returns = {
            "APPID": dict(key='application', convert_to='int', transform=self._get_application_name),
            "FIREWALLGROUPID": dict(key='firewallgroup', transform=self._get_firewallgroup_name),
            "SUBID": dict(key='id', convert_to='int'),
            "VPSPLANID": dict(key='plan', convert_to='int', transform=self._get_plan_name),
            "allowed_bandwidth_gb": dict(convert_to='float'),
            'auto_backups': dict(key='auto_backup_enabled', convert_to='bool'),
            "cost_per_month": dict(convert_to='float'),
            "current_bandwidth_gb": dict(convert_to='float'),
            "date_created": dict(),
            "default_password": dict(),
            "disk": dict(),
            "gateway_v4": dict(key='v4_gateway'),
            "internal_ip": dict(),
            "kvm_url": dict(),
            "label": dict(key='name'),
            "location": dict(key='region'),
            "main_ip": dict(key='v4_main_ip'),
            "netmask_v4": dict(key='v4_netmask'),
            "os": dict(),
            "pending_charges": dict(convert_to='float'),
            "power_status": dict(),
            "ram": dict(),
            "server_state": dict(),
            "status": dict(),
            "tag": dict(),
            "v6_main_ip": dict(),
            "v6_network": dict(),
            "v6_network_size": dict(),
            "v6_networks": dict(),
            "vcpu_count": dict(convert_to='int'),
        }

    def _get_application_name(self, application):
        if application == 0:
            return None

        return self.get_application(application, 'APPID').get('name')

    def _get_firewallgroup_name(self, firewallgroup):
        if firewallgroup == 0:
            return None

        return self.get_firewallgroup(firewallgroup, 'FIREWALLGROUPID').get('description')

    def _get_plan_name(self, plan):
        return self.get_plan(plan, 'VPSPLANID', optional=True).get('name') or 'N/A'

    def get_servers(self):
        return self.api_query(path="/v1/server/list")


def parse_servers_list(servers_list):
    return [server for id, server in servers_list.items()]


def main():
    argument_spec = vultr_argument_spec()

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    server_info = AnsibleVultrServerInfo(module)
    result = server_info.get_result(parse_servers_list(server_info.get_servers()))
    module.exit_json(**result)


if __name__ == '__main__':
    main()
