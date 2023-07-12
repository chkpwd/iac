![example workflow](https://github.com/ansible-collections/netapp.storagegrid/actions/workflows/main.yml/badge.svg)
[![codecov](https://codecov.io/gh/ansible-collections/netapp.storagegrid/branch/main/graph/badge.svg?token=weBYkksxSi)](https://codecov.io/gh/ansible-collections/netapp.storagegrid)
[![Discord](https://img.shields.io/discord/855068651522490400)](https://discord.gg/NetApp)


=============================================================

 netapp.storagegrid

 NetApp StorageGRID Collection

 Copyright (c) 2020 NetApp, Inc. All rights reserved.
 Specifications subject to change without notice.

=============================================================

# Installation

```bash
ansible-galaxy collection install netapp.storagegrid
```
To use this collection add the following to the top of your playbook.
```
collections:
  - netapp.storagegrid
```

# Usage

Each of the StorageGRID modules require an `auth_token` parameter to be specified. This can be obtained by executing a `uri` task against the StorageGRID Authorization API endpoint and registering the output as the first item in a Playbook.

If you are performing a Tenant operation, ensure that the `accountId` parameter is also specified in the URI body and set to the Tenant Account ID. For example, `"accountId": "01234567890123456789"`

```yaml
- name: Get Grid Authorization token
  uri:
    url: "https://sgadmin.example.com/api/v3/authorize"
    method: POST
    body: {
      "username": "root",
      "password": "storagegrid123",
      "cookie": false,
      "csrfToken": false
    }
    body_format: json
    validate_certs: false
  register: auth
```

Subsequent tasks can leverage the registered auth token.

```yaml
- name: Create a StorageGRID Tenant Account
  netapp.storagegrid.na_sg_grid_account:
    api_url: "https://sgadmin.example.com"
    auth_token: "{{ auth.json.data }}"
    validate_certs: false
    state: present
    name: AnsibleTenant
    protocol: s3
    management: true
    use_own_identity_source: true
    allow_platform_services: true
    password: "mytenantrootpassword"
    quota_size: 10
```

# Versioning

[Releasing, Versioning and Deprecation](https://github.com/ansible-collections/netapp/issues/93)

# Need help

Join our [Discord](https://discord.gg/NetApp)

# Code of Conduct

This collection follows the [Ansible project's Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).

# Release Notes

## 21.11.1

### Bug Fixes
  - na_sg_org_container - fix versioning not enabled on initial bucket creation.

## 21.11.0

### Minor Changes
  - na_sg_org_container - supports versioning configuration for S3 buckets available in StorageGRID 11.6+.

### New Modules
  - na_sg_grid_client_certificate - Manage Client Certificates on StorageGRID.
  
## 21.10.0

### Minor Changes
  - na_sg_grid_gateway - supports specifying HA Groups by name or UUID.

### Bug Fixes
  - na_sg_org_group - fixed behaviour where update to ``s3_policy`` is ignored if ``management_policy`` is set.

### New Modules
  - na_sg_grid_ha_group - Manage high availability (HA) group configuration on StorageGRID.
  - na_sg_grid_traffic_classes - Manage Traffic Classification Policy configuration on StorageGRID.
  
## 21.9.0
  
### Minor Changes
  - na_sg_grid_gateway - supports load balancer endpoint binding available in StorageGRID 11.5+.
  - na_sg_org_container - supports creation of S3 Object Lock buckets available in StorageGRID 11.5+.

### Bug Fixes
  - na_sg_grid_gateway - existing endpoints matched by ``name`` and ``port``.
  - na_sg_grid_account - minor documentation fix.

## 21.8.0

### Minor Changes
  - all modules - enable usage of Ansible module group defaults - for Ansible 2.12+.

## 21.7.0

### New Modules

- na_sg_grid_gateway: Manage Load balancer (gateway) endpoints

### Minor Changes
- Updated documentation - added RETURN block for each module

## 21.6.0

### New Modules

- na_sg_grid_certificate: Manage the Storage API and Grid Management certificates on StorageGRID.
- na_sg_grid_identity_federation: Manage Grid identity federation.
- na_sg_org_identity_federation: Manage Tenant identity federation.

### Minor Changes
- na_sg_org_container - supports deletion of buckets when `state` is set to `absent`.

### Bug Fixes
- na_sg_org_container - fix issue with applying compliance settings on buckets.

## 20.11.0

### New Modules

- na_sg_grid_info: Gather StorageGRID Grig subset information
- na_sg_org_info: Gather StorageGRID Org subset information

### Minor Changes

- na_sg_grid_account: new option `root_access_account` for granting initial root access permissions for the tenant to an existing federated group

## 20.10.0

### Breaking Changes

This version introduces a breaking change. All modules have been renamed from `nac_sg_*` to `na_sg_*`. Playbooks and Roles must be updated to match.

### Bug Fixes

- na_sg_grid_account: fixed documentation issue.
- na_sg_grid_account: added `no_log` flag to password fields
- na_sg_grid_group: fixed group name parsing
- na_sg_org_group: fixed group name parsing

### New Options

- na_sg_grid_account: new option `update_password` for managing Tenant Account root password changes
- na_sg_org_user: new option `password` and `update_password` for setting or updating Tenant User passwords
- na_sg_grid_user: new option `password` and `update_password` for setting or updating Grid Admin User passwords

## 20.6.1

### Minor Changes
- Fixed documentation issue in README.md

### Bug Fixes
- nac_sg_org_container: fixed documentation issue.

## 20.6.0

Initial release of NetApp StorageGRID Ansible modules

### New Modules

- nac_sg_grid_account: create/modify/delete Tenant account
- nac_sg_grid_dns: set Grid DNS servers
- nac_sg_grid_group: create/modify/delete Grid admin group
- nac_sg_grid_ntp: set Grid NTP servers
- nac_sg_grid_regions: set Grid Regions
- nac_sg_grid_user: create/modify/delete Grid admin user
- nac_sg_org_container: create S3 bucket
- nac_sg_org_group: create/modify/delete Tenant group
- nac_sg_org_user: create/modify/delete Tenant user
- nac_sg_org_user_s3_key: create/delete S3 key

