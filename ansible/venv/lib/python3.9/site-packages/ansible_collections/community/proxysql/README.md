# ProxySQL collection for Ansible
[![Plugins CI](https://github.com/ansible-collections/community.proxysql/workflows/Plugins%20CI/badge.svg?event=push)](https://github.com/ansible-collections/community.proxysql/actions?query=workflow%3A"Plugins+CI") [![Roles CI](https://github.com/ansible-collections/community.proxysql/workflows/Roles%20CI/badge.svg?event=push)](https://github.com/ansible-collections/community.proxysql/actions?query=workflow%3A"Roles+CI") [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.proxysql)](https://codecov.io/gh/ansible-collections/community.proxysql)

This collection is a part of the Ansible package.

## Code of Conduct

We follow [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Contributing to this collection

The content of this collection is made by good [people](https://github.com/ansible-collections/community.proxysql/blob/main/CONTRIBUTORS) just like you, a community of individuals collaborating on making the world better through developing automation software.

We are actively accepting new contributors.

All types of contributions are very welcome.

You don't know how to start? Refer to our [contribution guide](https://github.com/ansible-collections/community.proxysql/blob/main/CONTRIBUTING.md)!

## Collection maintenance

The current maintainers (contributors with `write` or higher access) are listed in the [MAINTAINERS](https://github.com/ansible-collections/community.proxysql/blob/main/MAINTAINERS) file. If you have questions or need help, feel free to mention them in the proposals.

To learn how to maintain / become a maintainer of this collection, refer to the [Maintainer guidelines](https://github.com/ansible-collections/community.proxysql/blob/main/MAINTAINING.md).

It is necessary for maintainers of this collection to be subscribed to:

* The collection itself (the `Watch` button -> `All Activity` in the upper right corner of the repository's homepage).
* The "Changes Impacting Collection Contributors and Maintainers" [issue](https://github.com/ansible-collections/overview/issues/45).

They also should be subscribed to Ansible's [The Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn).

## Communication

We announce important development changes and releases through Ansible's [The Bullhorn newsletter](https://eepurl.com/gZmiEP). If you are a collection developer, be sure you are subscribed.

Join us in the ``#ansible`` (general use questions and support), ``#ansible-community`` (community and collection development questions), and other [IRC channels](https://docs.ansible.com/ansible/devel/community/communication.html#irc-channels) on [Libera.Chat](https://libera.chat).

We take part in the global quarterly [Ansible Contributor Summit](https://github.com/ansible/community/wiki/Contributor-Summit) virtually or in-person. Track [The Bullhorn newsletter](https://eepurl.com/gZmiEP) and join us.

For more information about communication, refer to the [Ansible Communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Included content

- **Modules**:
  - `proxysql_backend_servers`: Adds or removes mysql hosts from proxysql admin interface.
  - `proxysql_global_variables`: Gets or sets the proxysql global variables.
  - `proxysql_info`: Gathers information about proxysql server.
  - `proxysql_manage_config`: Writes the proxysql configuration settings between layers.
  - `proxysql_mysql_users`: Adds or removes mysql users from proxysql admin interface.
  - `proxysql_query_rules_fast_routing.py`: Modifies query rules for fast routing policies using the proxysql admin interface.
  - `proxysql_query_rules`: Modifies query rules using the proxysql admin interface.
  - `proxysql_replication_hostgroups`: Manages replication hostgroups using the proxysql admin.
  - `proxysql_scheduler`: Adds or removes schedules from proxysql admin interface.
- **Roles**:
  - proxysql

Note: if you do not see documentation for a module on [docs.ansible.come](https://docs.ansible.com/ansible/devel/collections/community/proxysql/), use the [ansible-doc](https://docs.ansible.com/ansible/latest/cli/ansible-doc.html) command or see the `DOCUMENTATION` section in the `plugins/modules/<module_name>.py` file.

## Supports and tested with ansible-core

- 2.11
- 2.12
- 2.13
- current development version

## External requirements

The ProxySQL modules rely on a MySQL connector.  The list of supported drivers is below:

- [PyMySQL](https://github.com/PyMySQL/PyMySQL)
- [MySQLdb](https://github.com/PyMySQL/mysqlclient-python)
- Support for other Python MySQL connectors may be added in a future release.

## Using this collection

### Installing the Collection from Ansible Galaxy

Before using the ProxySQL collection, you need to install it with the Ansible Galaxy command-line tool:

```bash
ansible-galaxy collection install community.proxysql
```

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.proxysql
```

You can also download the tarball from [Ansible Galaxy](https://galaxy.ansible.com/community/proxysql) and install the collection manually wherever you need.

Note that if you install the collection from Ansible Galaxy with the command-line tool or tarball, it will not be upgraded automatically when you upgrade the Ansible package. To upgrade the collection to the latest available version, run the following command:

```bash
ansible-galaxy collection install community.proxysql --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax:

```bash
ansible-galaxy collection install community.proxysql:==X.Y.Z
```

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for more details.

## Licensing

GNU General Public License v3.0 or later.

See [LICENSE](https://www.gnu.org/licenses/gpl-3.0.txt) to see the full text.
