# Personas Deployment Guide
## Introduction

Once all ISE nodes have been deployed to AWS, we can use Ansible to build a multi-node ISE cluster with distinct ISE personas, such as Policy Administration nodes (PAN), Monitoring and Troubleshooting nodes (MNT), and Policy Services nodes (PSN).

**Note**: This role assumes the nodes have already been deployed to the AWS platform using the AWS Deployment role included in this collection. However, the role can be easily modified to suit any other needs, such as an on-prem deployment.
 
## Goal

The goals of this guide are:

1. Install the Ansible ISE collection
2. Configure the Personas Deployment role
3. Build a cluster and assign the correspondent personas to each node

## Pre-requisites

It is recommended that you review the following guides before starting this one:

- [ISE Ansible Getting Started Guide](./ansible_start_guide.md)
- [AWS Deployment Guide](./personas_deployment.md)


## Role information

The Personas Deployment Ansible role acomplishes the following tasks:

1. Checks whether or not all the nodes are in standalone mode. If not, the playbook exits with an error message.
2. Exports into the primary node the certificates of all the other nodes
3. Assigns the Primary PAN persona to one of the nodes
4. Assigns the corresponding personas to the rest of the nodes

## Deployment types
This role supports the following deployment types:

1. **Small**: Two nodes fulfilling the following roles:
    * **Node 1**: PPAN, MNT-ACTIVE and PSN
    * **Node 2**: SPAN, MNT-STANDBY and PSN
2. **Medium**: Up to seven nodes fulfilling the following roles:
    * **Node 1**: PPAN and MNT-ACTIVE
    * **Node 2**: SPAN and MNT-STANDBY
    * **Node 3 through Node 7**: PSN
3. **Large**: Up to 54 nodes fulfilling the following roles:
    * **Node 1**: PPAN
    * **Node 2**: SPAN
    * **Node 3**: MNT-ACTIVE
    * **Node 4**: MNT-STANDBY
    * **Node 5 to Node 54**: PSN

## Variables

Depending on the deployment type, the variables that need to be set are different. It is assumed that all nodes share the same credentials, as this is the default behavior of the AWS Deployment role. There are no default values for IP addresses, so all IP address variables must be specified.

### Variables common to all deployment types

- **ise_deployment_type**: Could be `small`, `medium` or `large`. Default: `small`
- **ise_username**: Username for the nodes. Default: `admin`
- **ise_password**: Password for the nodes. Default: `C1sco12345`
- **ise_domain**: Domain name. Default: `example.com`
- **ise_base_hostname**: The base hostname for the nodes. Default: `ISE`
- **pan1_ip**: Public IP address for the Primary PAN node.
- **pan2_ip**: Public IP address for the Secondary PAN node.

### Additional variables for medium or large deployments

- **psn1_ip**: Public IP address for the first PSN node
- **psn2_ip**: Public IP address for the second PSN node
- **psn*N*_ip**: Public IP address for the Nth PSN node

### Additional variables specific for large deployments

- **mnt1_ip**: Public IP address for the Active Monitoring node
- **mnt2_ip**: Public IP address for the Standby Monitoring node


## Role usage

Create a playbook that contains all the pertinent variables required by this role:

```yaml
# playbooks/personas_deployment.yml
# Example for a small deployment
---
- name: ISE Personas Deployment Playbook
  hosts: localhost
  connection: local
  vars:
    ise_deployment: small
    ise_username: admin
    ise_password: C1sco123
    ise_domain: example.com
    pan1_ip: 1.1.1.1
    pan2_ip: 2.2.2.2

  roles:
    - cisco.ise.personas_deployment
```

Run the Ansible playbook:

```cli
ansible-playbook -i hosts playbooks/personas_deployment.yml
```

### Sample playbooks for medium and large deployments

```yaml
# playbooks/personas_deployment.yml
# Example for a medium deployment
---
- name: ISE Personas Deployment Playbook
  hosts: localhost
  connection: local
  vars:
    ise_deployment: medium
    ise_username: admin
    ise_password: C1sco123
    ise_domain: example.com
    pan1_ip: 1.1.1.1
    pan2_ip: 2.2.2.2
    psn1_ip: 3.3.3.3
    psn2_ip: 4.4.4.4

  roles:
    - cisco.ise.personas_deployment
```

```yaml
# playbooks/personas_deployment.yml
# Example for a large deployment
---
- name: ISE Personas Deployment Playbook
  hosts: localhost
  connection: local
  vars:
    ise_deployment: large
    ise_username: admin
    ise_password: C1sco123
    ise_domain: example.com
    pan1_ip: 1.1.1.1
    pan2_ip: 2.2.2.2
    psn1_ip: 3.3.3.3
    psn2_ip: 4.4.4.4
    mnt1_ip: 5.5.5.5
    mnt2_ip: 6.6.6.6

  roles:
    - cisco.ise.personas_deployment
```