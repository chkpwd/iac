# cisco.intersight Ansible Collection

Ansible collection for managing and automating Cisco Intersight environments.  Modules and roles are provided for common Cisco Intersight tasks.  Detailed installation and usage examples are included in a lab guide in the misc directory of this collection at https://github.com/CiscoDevNet/intersight-ansible/blob/master/misc/CL2020%20EMEAR%20DEVWKS-1542%20Intersight%20Ansible%20Lab%20Guide.pdf 

* Note: This collection is not compatible with versions of Ansible before v2.8.

## Requirements

- Ansible v2.8 or newer
- Python 3 (Python 2 is no longer supported with this collection)


## Install
- ansible must be installed
```
sudo pip install ansible
```

## Usage

Authentication with the Intersight API requires the use of API keys that should be generated within the Intersight UI.  See (https://intersight.com/help) or (https://communities.cisco.com/docs/DOC-76947) for more information on generating and using API keys.
If you do not have an Intersight account, you can create one and claim devices in Intersight using the DevNet Intersight Sandbox at https://devnetsandbox.cisco.com/RM/Diagram/Index/a63216d2-e891-4856-9f27-309ca61ec862?diagramType=Topology
Because Intersight has a single API endpoint, minimal setup is required in playbooks or variables to access the API.  Here's an example playbook:
```
---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
  - name: Configure Boot Policy
    cisco.intersight.intersight_rest_api:
      api_private_key: <path to your private key>
      api_key_id: <your public key id>
      resource_path: /boot/PrecisionPolicies
      api_body: {
```

localhost (the Ansible controller) can be used without the need to specify any hosts or inventory.  Hosts can be specified to perform parallel actions.  An example of Server Firmware Update on multiple servers is provided by the server_firmware.yml playbook.

If you're using playbooks in this repo, you will need to provide your own inventory file and cusomtize any variables used in playbooks with settings for your environment.  This repo includes an example_inventory file with host groups for HX Clusters (Intersight_HX) and Servers (Intersight_Servers) and API key variables shared for Intersight host groups:
```
[Intersight_HX]
sjc07-r13-501
sjc07-r13-503

[Intersight_Servers]

[Intersight:children]
Intersight_HX
Intersight_Servers

[Intersight:vars]
api_private_key=~/Downloads/SecretKey.txt
api_key_id=...
```
For demo purposes, you can copy the example_inventory file to a new file named inventory.  Then, edit the inventory file to provide your own api_private_key location and api_key_id for use in playbooks.  If you're are using the Intersight Virtual Appliance, your inventory file can also specify the appliance URI and use of local certificates:
```
api_uri=https://tme-appliance2.intersightdemo.cisco.com/api/v1
validate_certs=false
```

Once you've provided API key information, the inventory file can be automatically updated with data from your Intersight account using one of the following playbooks:
- update_all_inventory.yml (if you'd like all Servers in the inventory)
- update_standalone_inventory.yml (if you'd like only Standalone C-Series Servers that can be managed through Server Policies/Profiles)

Here are example command lines for creating your own inventory and running the update_standalone_inventory.yml playbook:
```
cp example_inventory inventory
edit inventory with your api_private_key and api_key_id
ansible-playbook -i inventory update_standalone_inventory.yml
```
With an inventory for your Intersight account, you can now run playbooks to configure profiles/policies, and perform other server actions in Intersight:
```
ansible-playbook -i inventory cos_server_policies_and_profiles.yml --list-tasks --list-hosts (will show the tasks and their tags along with the hosts that will be configured)
ansible-playbook -i inventory cos_server_policies_and_profiles.yml (will configure policies and profiles in Intersight)
ansible-playbook -i inventory deploy_server_profiles.yml (note: this will deploy settings, run with --check to see what would change 1st)
ansible-playbook -i inventory server_actions.yml (note: by default this will PowerOn all servers, view the playbook to see other options)
```

Here are example command lines for creating an inventory with all Servers:
```
cp example_inventory inventory
edit inventory with your api_private_key and api_key_id
ansible-playbook -i inventory update_all_inventory.yml
```
# Community:

* We are on Slack (https://ciscoucs.slack.com/) - Slack requires registration, but the ucspython team is open invitation to
  anyone.  Click [here](https://ucspython.herokuapp.com) to register 