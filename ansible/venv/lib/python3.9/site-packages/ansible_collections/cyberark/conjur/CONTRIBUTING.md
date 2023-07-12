# Contributing to the Ansible Conjur Collection

Thanks for your interest in Conjur. Before contributing, please take a moment to
read and sign our <a href="https://github.com/cyberark/community/blob/master/documents/CyberArk_Open_Source_Contributor_Agreement.pdf" download="conjur_contributor_agreement">Contributor Agreement</a>.
This provides patent protection for all Conjur users and allows CyberArk to enforce
its license terms. Please email a signed copy to <a href="oss@cyberark.com">oss@cyberark.com</a>.
For general contribution and community guidelines, please see the [community repo](https://github.com/cyberark/community).

- [Contributing to the Ansible Conjur Collection](#contributing-to-the-ansible-conjur-collection)
  * [Prerequisites](#prerequisites)
  * [Set up a development environment](#set-up-a-development-environment)
    + [Verification](#verification)
    + [Useful links](#useful-links)
  * [Testing](#testing)
    + [Unit tests](#unit-tests)
    + [Integration tests](#integration-tests)
  * [Releasing](#releasing)
- [Ansible Conjur Collection Quick Start](#ansible-conjur-collection-quick-start)
  * [Setup a conjur OSS Environment](#setup-a-conjur-oss-environment)
  * [Load policy to set up Conjur Ansible integration](#load-policy-to-set-up-conjur-ansible-integration)
  * [Create Ansible managed nodes](#create-ansible-managed-nodes)
  * [Use Conjur Ansible Role to set up identity on managed nodes](#use-conjur-ansible-role-to-set-up-identity-on-managed-nodes)
  * [Use Conjur Lookup Plugin to provide secrets to Ansible Playbooks](#use-conjur-lookup-plugin-to-provide-secrets-to-ansible-playbooks)

<small><i><a href='http://ecotrust-canada.github.io/markdown-toc/'>Table of contents generated with markdown-toc</a></i></small>

## Prerequisites

Before getting started, the following tools need to be installed:

1. [Git][get-git] to manage source code
2. [Docker][get-docker] to manage dependencies and runtime environments
3. [Docker Compose][get-docker-compose] to orchestrate Docker environments

[get-docker]: https://docs.docker.com/engine/installation
[get-docker-compose]: https://docs.docker.com/compose/install
[get-git]: https://git-scm.com/downloads

## Set up a development environment

The `dev` directory contains a `docker-compose` file which creates a development
environment :
-  A Conjur Open Source instance
-  An Ansible control node
-  Managed nodes to push tasks to

To use it:

1. Install dependencies (as above)

1. To use the dev environment, clone the
   [Collection repository](https://github.com/cyberark/ansible-conjur-collection)
   and run the setup script:

   ```sh-session
   $ git clone https://github.com/cyberark/ansible-conjur-collection.git
   $ cd ansible-conjur-collection/dev
   $ ./start.sh
   ```

### Verification

When the Conjur and Ansible containers have been successfully setup, the
terminal prints the following:

```sh-session
  ...
  PLAY RECAP *********************************************************************
  ansibleplugingtestingconjurhostidentity-test_app_centos-1 : ok=17 ...
  ansibleplugingtestingconjurhostidentity-test_app_centos-2 : ok=17 ...
  ansibleplugingtestingconjurhostidentity-test_app_ubuntu-1 : ok=16 ...
  ansibleplugingtestingconjurhostidentity-test_app_ubuntu-2 : ok=16 ...
  ```

Your Conjur instance will be configured with the following:
* Account: `cucumber`
* User: `admin`
* Password: Run `conjurctl role retrieve-key cucumber:user:admin` inside the
  Conjur container shell to retrieve the admin user API key

### Useful links

- [Official documentation for Conjur's Ansible integration](https://docs.conjur.org/Latest/en/Content/Integrations/ansible.html)
- [Conjur Collection on Ansible Galaxy](https://galaxy.ansible.com/cyberark/conjur)
- [Ansible documentation for the Conjur collection](https://docs.ansible.com/ansible/latest/collections/cyberark/conjur/index.html)

## Testing

### Unit tests

Unit tests are only available for the Conjur Variable Lookup plugin. To run
these tests:
```
./dev/test_unit.sh
```

### Integration tests

The collection has integration tests for both the Variable Lookup plugin and the
Host Identity role that will validate each against live Conjur and Ansible
containers.

To run all tests:
```
./ci/test.sh -a
```

To run the tests for a particular module:
```
./ci/test.sh -d <role or plugin name>
```

Integration tests can be run against Conjur Enterprise by adding the `-e` flag:
```
./ci/test/sh -e -a
```

## Releasing

From a clean instance of main, perform the following actions to release a new version
of this plugin:

- Update the version number in [`galaxy.yml`](galaxy.yml) and [`CHANGELOG.md`](CHANGELOG.md)
    - Verify that all changes for this version in `CHANGELOG.md` are clear and accurate,
      and are followed by a link to their respective issue
    - Create a PR with these changes

- Create an annotated tag with the new version, formatted as `v##.##.##`
    - This will kick off an automated script which publish the release to
      [Ansible Galaxy](https://galaxy.ansible.com/cyberark/conjur)

- Create the release on GitHub for that tag
    - Build the release package with `./ci/build_release`
    - Attach package to Github Release


# Ansible Conjur Collection Quick Start

## Setup a conjur OSS Environment

Generate the master key, which will be used to encrypt Conjur's database. Store
this value as an environment variable.

```sh-session
docker-compose run --no-deps --rm conjur data-key generate > data_key
export CONJUR_DATA_KEY="$(< data_key)"
```

Start the Conjur OSS environment. An account, named `cucumber`, will be
automatically created.

```sh-session
docker-compose up -d conjur
```

Retrieve the admin user's API key, and store the value in an environment variable.

```sh-session
export CLI_CONJUR_AUTHN_API_KEY="$(docker-compose exec conjur conjurctl role retrieve-key cucumber:user:admin)"
```

Start the Conjur CLI container. The CLI will be automatically authenticated as
the user `cucumber:user:admin`.

```sh-session
docker-compose up -d conjur_cli
```

## Load policy to set up Conjur Ansible integration

Policy defines Conjur entities and the relationships between them. An entity can
be a policy, a host, a user, a layer, a group, or a variable.

Check out the policy file, and load it into Conjur:

```sh-session
docker-compose exec conjur_cli cat /policy/root.yml
docker-compose exec conjur_cli conjur policy load root /policy/root.yml
```

Also, load a dummy secret value into the `ansible/target-password` variable.
This is a variable required by remote nodes in order to complete their workloads.

```sh-session
docker-compose exec conjur_cli conjur variable values add ansible/target-password S3cretV@lue
```

## Create Ansible managed nodes

The Ansible environment will include a control node and a number of managed
nodes. First, retrieve the API key for the Conjur host representing the control
node, then create it:

```sh-session
export ANSIBLE_CONJUR_AUTHN_API_KEY="$(docker-compose exec conjur conjurctl role retrieve-key cucumber:host:ansible/ansible-master)"
docker-compose up -d ansible
```

Next, create two instances of each managed node:

```sh-session
docker-compose up -d --scale test_app_ubuntu=2 test_app_ubuntu
docker-compose up -d --scale test_app_centos=2 test_app_centos
```

## Use Conjur Ansible Role to set up identity on managed nodes

To grant your Ansible host a Conjur identity, first install the Conjur
Collection on your Ansible control node:

```sh-session
docker-compose exec ansible ansible-galaxy collection install cyberark.conjur
```

Set up the host factory token in the HFTOKEN env var

```sh-session
export HFTOKEN="$(docker-compose exec conjur_cli conjur hostfactory tokens create ansible/ansible-factory | jq -r '.[0].token')"
```

Once you've done this, you can configure each Ansible node with a Conjur
identity by including a section like the example below in your Ansible playbook:

```yaml
---
- hosts: testapp
  roles:
    - role: cyberark.conjur.conjur_host_identity
      conjur_appliance_url: 'https://conjur.myorg.com',
      conjur_account: 'cucumber',
      conjur_host_factory_token: "{{lookup('env', 'HFTOKEN')}}",
      conjur_host_name: "{{inventory_hostname}}"
```

First we register the host with Conjur, adding it into the layer specific to the
provided host factory token, and then install Summon with the Summon Conjur
provider for secret retrieval from Conjur.

## Use Conjur Lookup Plugin to provide secrets to Ansible Playbooks

The Conjur lookup plugin can inject secret data directly into an Ansible
playbook, like it the following example:

```yaml
---
- hosts: testapp
  tasks:
  - name: Provide secret with Lookup plugin
    debug:
      msg: "{{ lookup('cyberark.conjur.conjur_variable', '/ansible/target-password') }}"
```
