# Check Point Ansible Mgmt Collection
This Ansible collection provides control over a Check Point Management server using
Check Point's web-services APIs.

The Ansible Check Point modules reference can be found here:
https://docs.ansible.com/ansible/latest/collections/check_point/mgmt/index.html#plugins-in-check-point-mgmt
<br>Note - look only at the `cp_mgmt_*` modules, cause the `checkpoint_*` will be deprecated.

This is the repository of the mgmt collection which can be found here - https://galaxy.ansible.com/check_point/mgmt

Installation instructions
-------------------------
Run `ansible-galaxy collection install check_point.mgmt`

Requirements
------------
* Ansible 2.9+ is required.
* The Check Point server should be using the versions detailed in this SK: https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk114661
* The Check Point server should be open for API communication from the Ansible server.
  Open SmartConsole and check "Manage & Settings > Blades > Management API > Advanced settings".

Usage
-----
1. Edit the `hosts` so that it will contain a section similar to this one:
```
[check_point]
%CHECK_POINT_MANAGEMENT_SERVER_IP%
[check_point:vars]
ansible_httpapi_use_ssl=True
ansible_httpapi_validate_certs=False
ansible_user=%CHECK_POINT_MANAGEMENT_SERVER_USER%
ansible_password=%CHECK_POINT_MANAGEMENT_SERVER_PASSWORD%
ansible_network_os=check_point.mgmt.checkpoint
```
Note - If you want to run against Ansible version 2.9 instead of the collection, just replace `ansible_network_os=check_point.mgmt.checkpoint` with `ansible_network_os=checkpoint`
<br><br>2. Run a playbook:
```sh
ansible-playbook your_ansible_playbook.yml
```
or

Run a playbook in "check mode":
```sh
ansible-playbook -C your_ansible_playbook.yml
```
Example playbook:
```
---
- name: playbook name
  hosts: check_point
  connection: httpapi
  tasks:
    - name: task to have network
      check_point.mgmt.cp_mgmt_network:
        name: "network name"
        subnet: "4.1.76.0"
        mask_length: 24
        auto_publish_session: true
        
      vars: 
        ansible_checkpoint_domain: "SMC User"
```
Note - If you want to run against Ansible version 2.9 instead of the collection, just replace `check_point.mgmt.cp_mgmt_network` with `cp_mgmt_network`

###  Notes:
  1. Because this Ansible module is controlling the management server remotely via the web API, 
     the Ansible server needs to have access to the Check Point API server.
     Open `SmartConsole`, navigate to "Manage & Settings > Blades > Management API > Advanced settings"
     and check the API server's accessibility set
  2. Ansible has a feature called "Check Mode" that enables you to test the
     changes without actually changing anything.
  3. The login and logout happens automatically.
  4. If you want to login to a specific domain, in the playbook above in the `vars`secion change the domain name to 
     `ansible_checkpoint_domain`
  5. There are two ways to publish changes:
    a. Set the `auto_publish_session` to `true` as displayed in the example playbook above.
       This option will publish only the task which this parameter belongs to.
    b. Add the task to publish to the `cp_mgmt_publish` module.
       This option will publish all the tasks above this task.
  6. It is recommended by Check Point to use this collection over the modules of Ansible version 2.9
  7. If you still want to use Ansible version 2.9 instead of this collection (not recommended):
    a. In the `hosts` file replace `ansible_network_os=check_point.mgmt.checkpoint` with `ansible_network_os=checkpoint`
    b. In the task in the playbook replace the module `check_point.mgmt.cp_mgmt_*` with the module `cp_mgmt_*`
  8. Starting from version 1.0.6, when running a command which returns a task-id, and the user chooses to wait for that task to finish
     (the default is to wait), then the output of the command will be the output of the show-task command (instead of the task-id).

Modules
-------
* `cp_mgmt_access_layer` – Manages access-layer objects on Check Point over Web Services API
* `cp_mgmt_access_layer_facts` – Get access-layer objects facts on Check Point over Web Services API
* `cp_mgmt_access_role` – Manages access-role objects on Check Point over Web Services API
* `cp_mgmt_access_role_facts` – Get access-role objects facts on Check Point over Web Services API
* `cp_mgmt_access_rule` – Manages access-rule objects on Check Point over Web Services API
* `cp_mgmt_access_rules` – Manages a list of access rules objects on Check Point over Web Services API
* `cp_mgmt_access_rule_facts` – Get access-rule objects facts on Check Point over Web Services API
* `cp_mgmt_address_range` – Manages address-range objects on Check Point over Web Services API
* `cp_mgmt_address_range_facts` – Get address-range objects facts on Check Point over Web Services API
* `cp_mgmt_administrator` – Manages administrator objects on Check Point over Web Services API
* `cp_mgmt_administrator_facts` – Get administrator objects facts on Check Point over Web Services API
* `cp_mgmt_application_site` – Manages application-site objects on Check Point over Web Services API
* `cp_mgmt_application_site_category` – Manages application-site-category objects on Check Point over Web Services API
* `cp_mgmt_application_site_category_facts` – Get application-site-category objects facts on Check Point over Web Services API
* `cp_mgmt_application_site_facts` – Get application-site objects facts on Check Point over Web Services API
* `cp_mgmt_application_site_group` – Manages application-site-group objects on Check Point over Web Services API
* `cp_mgmt_application_site_group_facts` – Get application-site-group objects facts on Check Point over Web Services API
* `cp_mgmt_assign_global_assignment` – assign global assignment on Check Point over Web Services API
* `cp_mgmt_discard` – All changes done by user are discarded and removed from database
* `cp_mgmt_dns_domain` – Manages dns-domain objects on Check Point over Web Services API
* `cp_mgmt_dns_domain_facts` – Get dns-domain objects facts on Check Point over Web Services API
* `cp_mgmt_dynamic_object` – Manages dynamic-object objects on Check Point over Web Services API
* `cp_mgmt_dynamic_object_facts` – Get dynamic-object objects facts on Check Point over Web Services API
* `cp_mgmt_exception_group` – Manages exception-group objects on Check Point over Web Services API
* `cp_mgmt_exception_group_facts` – Get exception-group objects facts on Check Point over Web Services API
* `cp_mgmt_global_assignment` – Manages global-assignment objects on Check Point over Web Services API
* `cp_mgmt_global_assignment_facts` – Get global-assignment objects facts on Check Point over Web Services API
* `cp_mgmt_group` – Manages group objects on Check Point over Web Services API
* `cp_mgmt_group_facts` – Get group objects facts on Check Point over Web Services API
* `cp_mgmt_group_with_exclusion` – Manages group-with-exclusion objects on Check Point over Web Services API
* `cp_mgmt_group_with_exclusion_facts` – Get group-with-exclusion objects facts on Check Point over Web Services API
* `cp_mgmt_host` – Manages host objects on Check Point over Web Services API
* `cp_mgmt_host_facts` – Get host objects facts on Check Point over Web Services API
* `cp_mgmt_install_policy` – install policy on Check Point over Web Services API
* `cp_mgmt_install_database` – install database on Check Point over Web Services API
* `cp_mgmt_mds` – Multi-Domain Server (mds) objects on Check Point over Web Services API
* `cp_mgmt_mds_facts` – Get Multi-Domain Server (mds) objects facts on Check Point over Web Services API
* `cp_mgmt_multicast_address_range` – Manages multicast-address-range objects on Check Point over Web Services API
* `cp_mgmt_multicast_address_range_facts` – Get multicast-address-range objects facts on Check Point over Web Services API
* `cp_mgmt_network` – Manages network objects on Check Point over Web Services API
* `cp_mgmt_network_facts` – Get network objects facts on Check Point over Web Services API
* `cp_mgmt_package` – Manages package objects on Check Point over Web Services API
* `cp_mgmt_package_facts` – Get package objects facts on Check Point over Web Services API
* `cp_mgmt_publish` – All the changes done by this user will be seen by all users only after publish is called
* `cp_mgmt_put_file` – put file on Check Point over Web Services API
* `cp_mgmt_run_ips_update` – Runs IPS database update. If "package-path" is not provided server will try to get the latest package from the User Center
* `cp_mgmt_run_script` – Executes the script on a given list of targets
* `cp_mgmt_security_zone` – Manages security-zone objects on Check Point over Web Services API
* `cp_mgmt_security_zone_facts` – Get security-zone objects facts on Check Point over Web Services API
* `cp_mgmt_service_dce_rpc` – Manages service-dce-rpc objects on Check Point over Web Services API
* `cp_mgmt_service_dce_rpc_facts` – Get service-dce-rpc objects facts on Check Point over Web Services API
* `cp_mgmt_service_group` – Manages service-group objects on Check Point over Web Services API
* `cp_mgmt_service_group_facts` – Get service-group objects facts on Check Point over Web Services API
* `cp_mgmt_service_icmp` – Manages service-icmp objects on Check Point over Web Services API
* `cp_mgmt_service_icmp6` – Manages service-icmp6 objects on Check Point over Web Services API
* `cp_mgmt_service_icmp6_facts` – Get service-icmp6 objects facts on Check Point over Web Services API
* `cp_mgmt_service_icmp_facts` – Get service-icmp objects facts on Check Point over Web Services API
* `cp_mgmt_service_other` – Manages service-other objects on Check Point over Web Services API
* `cp_mgmt_service_other_facts` – Get service-other objects facts on Check Point over Web Services API
* `cp_mgmt_service_rpc` – Manages service-rpc objects on Check Point over Web Services API
* `cp_mgmt_service_rpc_facts` – Get service-rpc objects facts on Check Point over Web Services API
* `cp_mgmt_service_sctp` – Manages service-sctp objects on Check Point over Web Services API
* `cp_mgmt_service_sctp_facts` – Get service-sctp objects facts on Check Point over Web Services API
* `cp_mgmt_service_tcp` – Manages service-tcp objects on Check Point over Web Services API
* `cp_mgmt_service_tcp_facts` – Get service-tcp objects facts on Check Point over Web Services API
* `cp_mgmt_service_udp` – Manages service-udp objects on Check Point over Web Services API
* `cp_mgmt_service_udp_facts` – Get service-udp objects facts on Check Point over Web Services API
* `cp_mgmt_session_facts` – Get session objects facts on Check Point over Web Services API
* `cp_mgmt_simple_gateway` – Manages simple-gateway objects on Check Point over Web Services API
* `cp_mgmt_simple_gateway_facts` – Get simple-gateway objects facts on Check Point over Web Services API
* `cp_mgmt_tag` – Manages tag objects on Check Point over Web Services API
* `cp_mgmt_tag_facts` – Get tag objects facts on Check Point over Web Services API
* `cp_mgmt_threat_exception` – Manages threat-exception objects on Check Point over Web Services API
* `cp_mgmt_threat_exception_facts` – Get threat-exception objects facts on Check Point over Web Services API
* `cp_mgmt_threat_indicator` – Manages threat-indicator objects on Check Point over Web Services API
* `cp_mgmt_threat_indicator_facts` – Get threat-indicator objects facts on Check Point over Web Services API
* `cp_mgmt_threat_layer` – Manages threat-layer objects on Check Point over Web Services API
* `cp_mgmt_threat_layer_facts` – Get threat-layer objects facts on Check Point over Web Services API
* `cp_mgmt_threat_profile` – Manages threat-profile objects on Check Point over Web Services API
* `cp_mgmt_threat_profile_facts` – Get threat-profile objects facts on Check Point over Web Services API
* `cp_mgmt_threat_protection_override` – Edit existing object using object name or uid
* `cp_mgmt_threat_rule` – Manages threat-rule objects on Check Point over Web Services API
* `cp_mgmt_threat_rule_facts` – Get threat-rule objects facts on Check Point over Web Services API
* `cp_mgmt_time` – Manages time objects on Check Point over Web Services API
* `cp_mgmt_time_facts` – Get time objects facts on Check Point over Web Services API
* `cp_mgmt_verify_policy` – Verifies the policy of the selected package
* `cp_mgmt_vpn_community_meshed` – Manages vpn-community-meshed objects on Check Point over Web Services API
* `cp_mgmt_vpn_community_meshed_facts` – Get vpn-community-meshed objects facts on Check Point over Web Services API
* `cp_mgmt_vpn_community_star` – Manages vpn-community-star objects on Check Point over Web Services API
* `cp_mgmt_vpn_community_star_facts` – Get vpn-community-star objects facts on Check Point over Web Services API
* `cp_mgmt_wildcard` – Manages wildcard objects on Check Point over Web Services API
* `cp_mgmt_wildcard_facts` – Get wildcard objects facts on Check Point over Web Services API
* `cp_mgmt_add_domain` – Add new domain on Check Point over Web Services API
* `cp_mgmt_set_domain` – Edit existing domain on Check Point over Web Services API
* `cp_mgmt_delete_domain` – Delete existing domain on Check Point over Web Services API
* `cp_mgmt_domain_facts` – Get domain objects on Check Point over Web Services API
* `cp_mgmt_trusted_client` – Trusted client objects on Check Point over Web Services API
* `cp_mgmt_trusted_client_facts` – Get trusted client objects facts on Check Point over Web Services API
* `cp_mgmt_identity_tag` – Identity tag objects on Check Point over Web Services API
* `cp_mgmt_identity_tag_facts` – Get identity tag objects facts on Check Point over Web Services API
