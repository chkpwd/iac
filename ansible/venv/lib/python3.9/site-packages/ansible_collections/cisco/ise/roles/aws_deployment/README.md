# AWS Deployment Guide
## Introduction

It is possible to deploy the Cisco Identity Service Enginer (ISE) on AWS using the official Cisco ISE AMI. The following guide explains how to use the Ansible role created for such task.

## Goal

The goals of this guide are:

1. Install the ansible role
2. Configure the role
3. Deploy to AWS

## Pre-requisites

It is recommended that you review the following guide before starting this one:

- [ISE Ansible Getting started guide](./ansible-start-guide.md)

## Role information

Within the recently installed Ansible collection, comes an AWS deployment role which can be configured using variables.

The role can be used like this:

```yaml
---
- name: ISE Deployment Playbook
  hosts: localhost
  connection: local

  roles:
    - cisco.ise.aws_deployment
```

The role accomplishes the following tasks:

1. Create an AWS Virtual Private Cloud (VPC)
2. Create an AWS subnet within the previously created VPC
3. Create an AWS Security Group (SG) on the VPC .
4. Create and store in the local filesystem an AWS key pair.
5. Deploy the selected ISE servers configuration.

## Variables

The role behavior can be changed using the following variables:

- **ise_base_hostname**: Servers base hostname. Default: ISE
- **ise_username**: Servers default username. Default: admin
- **ise_password**: Servers default password. Default: C1sco12345
- **ise_ntp_server**: NTP server. Default: 10.10.0.1
- **ise_dns_server**: DNS Server. Default: 10.10.0.1
- **ise_domain**: Domain name. Default: example.com
- **ise_timezone**: Timezones based on RFC. Default: Etc/UTC
- **aws_ise_ami**: Cisco ISE AWS AMI ID, for example, ami-0a8b4f863885c3372
- **aws_vpc_name**: AWS VPC. Default: ISE VPC
- **aws_vpc_cidr**: AWS VPC CIDR. Default: 10.10.0.0/16
- **aws_subnet_cidr**: AWS Subnet CIDR. Default: 10.10.1.0/24
- **aws_region**: AWS deployment region. Default: us-west-2
- **aws_public_access_cidr**: Network from where public access will be available. Default: 0.0.0.0/0
- **aws_keypair_name**: AWS SSH Key Pair name. Default: ISE-Deployment
- **aws_instance_type**: AWS Instance type for ISE servers. Default: c5.4xlarge

### Using variables in Ansible

There are several ways of modifying the default variables. You can check the [Ansible documentation](https://docs.ansible.com/ansible/latest/user_guide/playbooks_variables.html) for more information.

#### Command line

From the command line, it can be done with the `-e EXTRA_VARS` or `--extra-vars EXTRA_VARS` flag:
```cli
ansible-playbook -i hosts playbooks/aws_deployment.yml -e "aws_ise_ami='ami-0a8b4f863885c3372'"
```
```cli
ansible-playbook -i hosts playbooks/aws_deployment.yml --extra-vars "aws_ise_ami='ami-0a8b4f863885c3372'"
```

#### Variables file

It is possible to use a variables file:

```yaml
---
- name: ISE Deployment Playbook
  hosts: localhost
  connection: local
  vars_files:
    - my_vars.yml

  roles:
    - cisco.ise.aws_deployment
```

#### Playbook variables

You can define the variables in the playbook:

```yaml
---
- name: ISE Deployment Playbook
  hosts: localhost
  connection: local
  vars:
    aws_ise_ami: ami-0a8b4f863885c3372

  roles:
    - cisco.ise.aws_deployment
```

## Role usage

There are 4 possible deployment types supported by this role:

1. Single
2. Small
3. Medium
4. Large

### Single deployment

Set the `ise_deployment_type` variable to `single`. This deployment type creates one ISE server.

```cli
ansible-playbook -i hosts playbooks/aws_deployment.yml -e "ise_deployment_type=single"
```

### Small deployment

Set the `ise_deployment_type` variable to `small`. This deployment type creates two ISE servers.

```cli
ansible-playbook -i hosts playbooks/aws_deployment.yml -e "ise_deployment_type=small"
```

### Medium deployment

Set the `ise_deployment_type` variable to `medium`. This deployment type creates two servers with the PAN and MNT roles and up to five servers with the PSN role. It takes the extra variable `ise_psn_instances` to specify how many PSN servers should be created . For example, this would be the command for a deployment with two PSN servers:

```cli
ansible-playbook -i hosts playbooks/aws_deployment.yml -e "ise_deployment_type=medium ise_psn_instances=2"
```

### Large deployment

Set the `ise_deployment_type` variable to `large`. This deployment type creates two servers with the PAN role, two servers with the MNT role and up to 50 servers with the PSN role. It takes the extra variable `ise_psn_instances` to specify how many PSN servers should be created . For example, this would be the command for a deployment with two PSN servers:

```cli
ansible-playbook -i hosts playbooks/aws_deployment.yml -e "ise_deployment_type=large ise_psn_instances=2"
```
