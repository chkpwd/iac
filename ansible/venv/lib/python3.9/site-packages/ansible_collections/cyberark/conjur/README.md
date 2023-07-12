# CyberArk Ansible Conjur Collection

This collection contains components to be used with CyberArk Conjur & Conjur Enterprise
hosted in [Ansible Galaxy](https://galaxy.ansible.com/cyberark/conjur).

## Table of Contents

* [Certification Level](#certification-level)
* [Requirements](#requirements)
* [Installation](#installation)
* [Conjur Ansible Role](#conjur-ansible-role)
  + [Usage](#usage)
  + [Role Variables](#role-variables)
  + [Example Playbook](#example-playbook)
  + [Summon & Service Managers](#summon---service-managers)
  + [Recommendations](#recommendations)
* [Conjur Ansible Lookup Plugin](#conjur-ansible-lookup-plugin)
  + [Environment variables](#environment-variables)
  + [Role Variables](#role-variables-1)
  + [Examples](#examples)
    - [Retrieve a secret in a Playbook](#retrieve-a-secret-in-a-playbook)
    - [Retrieve a private key in an Inventory file](#retrieve-a-private-key-in-an-inventory-file)
* [Contributing](#contributing)
* [License](#license)

<!-- Table of contents generated with markdown-toc
http://ecotrust-canada.github.io/markdown-toc/ -->

## Certification Level

![](https://img.shields.io/badge/Certification%20Level-Certified-6C757D?link=https://github.com/cyberark/community/blob/main/Conjur/conventions/certification-levels.md)

This repo is a **Certified** level project. It's been reviewed by CyberArk to
verify that it will securely work with CyberArk Enterprise as documented. In
addition, CyberArk offers Enterprise-level support for these features. For more
detailed information on our certification levels, see
[our community guidelines](https://github.com/cyberark/community/blob/main/Conjur/conventions/certification-levels.md#community).

## Requirements

- An instance of [CyberArk Conjur Open Source](https://www.conjur.org) v1.x+ or [CyberArk
  Conjur Enterprise](https://docs.cyberark.com/Product-Doc/OnlineHelp/AAM-DAP/Latest/en/Content/Resources/_TopNav/cc_Home.htm)
  (formerly DAP) v10.x+ accessible from the target node
- Ansible >= 2.9

## Using ansible-conjur-collection with Conjur Open Source

Are you using this project with [Conjur Open Source](https://github.com/cyberark/conjur)? Then we
**strongly** recommend choosing the version of this project to use from the latest [Conjur OSS
suite release](https://docs.conjur.org/Latest/en/Content/Overview/Conjur-OSS-Suite-Overview.html).
Conjur maintainers perform additional testing on the suite release versions to ensure
compatibility. When possible, upgrade your Conjur version to match the
[latest suite release](https://docs.conjur.org/Latest/en/Content/ReleaseNotes/ConjurOSS-suite-RN.htm);
when using integrations, choose the latest suite release that matches your Conjur version. For any
questions, please contact us on [Discourse](https://discuss.cyberarkcommons.org/c/conjur/5).

## Installation 

From terminal, run the following command:
```sh
ansible-galaxy collection install cyberark.conjur
```

## Conjur Ansible Role

This Ansible role provides the ability to grant Conjur machine identity to a host. Based on that
identity, secrets can then be retrieved securely using the [Conjur Lookup
Plugin](#conjur-ansible-lookup-plugin) or using the [Summon](https://github.com/cyberark/summon)
tool (installed on hosts with identities created by this role).

### Usage

The Conjur role provides a method to establish the Conjur identity of a remote node with Ansible.
The node can then be granted least-privilege access to retrieve the secrets it needs in a secure
manner.

### Role Variables

* `conjur_appliance_url` _(Required)_: URL of the running Conjur service
* `conjur_account` _(Required)_: Conjur account name
* `conjur_host_factory_token` _(Required)_: [Host
  Factory](https://developer.conjur.net/reference/services/host_factory/) token for layer
  enrollment. This should be specified in the environment on the Ansible controlling host.
* `conjur_host_name` _(Required)_: Name of the host to be created.
* `conjur_ssl_certificate`: Public SSL certificate of the Conjur endpoint
* `conjur_validate_certs`: Boolean value to indicate if the Conjur endpoint should validate
  certificates
* `state`: Specifies whether to install of uninstall the Role on the specified nodes
* `summon.version`: version of Summon to install. Default is `0.8.2`.
* `summon_conjur.version`: version of Summon-Conjur provider to install. Default is `0.5.3`.

The variables not marked _`(Required)`_ are required for running with an HTTPS Conjur endpoint.

### Example Playbook

Configure a remote node with a Conjur identity and Summon:
```yml
- hosts: servers
  roles:
    - role: cyberark.conjur.conjur_host_identity
      conjur_appliance_url: 'https://conjur.myorg.com'
      conjur_account: 'myorg'
      conjur_host_factory_token: "{{ lookup('env', 'HFTOKEN') }}"
      conjur_host_name: "{{ inventory_hostname }}"
      conjur_ssl_certificate: "{{ lookup('file', '/path/to/conjur.pem') }}"
      conjur_validate_certs: yes
```

This example:
- Registers the host `{{ inventory_hostname }}` with Conjur, adding it into the Conjur policy layer
  defined for the provided host factory token.
- Installs Summon with the Summon Conjur provider for secret retrieval from Conjur.

### Role Cleanup

Executing the following playbook will clean up configuration and identity files
written to the specified remote nodes, as well as uninstalling Summon and the
Summon Conjur provider:
```yml
- hosts: servers
  roles:
    - role: cyberark.conjur.conjur_host_identity
      state: absent
```

### Summon & Service Managers

With Summon installed, using Conjur with a Service Manager (like systemd) becomes a snap. Here's a
simple example of a `systemd` file connecting to Conjur:

```ini
[Unit]
Description=DemoApp
After=network-online.target

[Service]
User=DemoUser
#Environment=CONJUR_MAJOR_VERSION=4
ExecStart=/usr/local/bin/summon --yaml 'DB_PASSWORD: !var staging/demoapp/database/password' /usr/local/bin/myapp
```

> Note: When connecting to Conjur 4 (Conjur Enterprise), Summon requires the environment variable
`CONJUR_MAJOR_VERSION` set to `4`. You can provide it by uncommenting the relevant line above.

The above example uses Summon to retrieve the password stored in `staging/myapp/database/password`,
set it to an environment variable `DB_PASSWORD`, and provide it to the demo application process.
Using Summon, the secret is kept off disk. If the service is restarted, Summon retrieves the
password as the application is started.

### Recommendations

- Add `no_log: true` to each play that uses sensitive data, otherwise that data can be printed to
  the logs.

- Set the Ansible files to minimum permissions. Ansible uses the permissions of the user that runs
  it.

## Conjur Ansible Lookup Plugin

Fetch credentials from CyberArk Conjur using the controlling host's Conjur identity or environment
variables.

The controlling host running Ansible must have a Conjur identity, provided for example by the
[ConjurAnsible role](#conjur-ansible-role).

### Environment variables

The following environment variables will be used by the lookup plugin to authenticate with the
Conjur host, if they are present on the system running the lookup plugin.

- `CONJUR_ACCOUNT` : The Conjur account name
- `CONJUR_APPLIANCE_URL` : URL of the running Conjur service
- `CONJUR_CERT_FILE` : Path to the Conjur certificate file
- `CONJUR_AUTHN_LOGIN` : A valid Conjur host username
- `CONJUR_AUTHN_API_KEY` : The api key that corresponds to the Conjur host username
- `CONJUR_AUTHN_TOKEN_FILE` : Path to a file containing a valid Conjur auth token

### Role Variables

None.

### Examples

#### Retrieve a secret in a Playbook
 
```yaml
---
- hosts: localhost
  tasks:
  - name: Lookup variable in Conjur
    debug:
      msg: "{{ lookup('cyberark.conjur.conjur_variable', '/path/to/secret') }}"
```

#### Retrieve a private key in an Inventory file

```yaml
---
ansible_host: <host>
ansible_ssh_private_key_file: "{{ lookup('cyberark.conjur.conjur_variable', 'path/to/secret-id', as_file=True) }}"
```

**Note:** Using the `as_file=True` condition, the private key is stored in a temporary file and its path is written 
in `ansible_ssh_private_key_file`.

## Contributing

We welcome contributions of all kinds to this repository. For instructions on how to get started and
descriptions of our development workflows, please see our [contributing guide][contrib].

[contrib]: https://github.com/cyberark/ansible-conjur-collection/blob/main/CONTRIBUTING.md

## License

Copyright (c) 2020 CyberArk Software Ltd. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.

For the full license text see [`LICENSE`](LICENSE).
