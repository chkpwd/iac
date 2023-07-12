# Ansible Collection: chocolatey.chocolatey

|                   Build Status                   |
| :----------------------------------------------: |
| [![Build Status][pipeline-badge]][pipeline-link] |

The `chocolatey.chocolatey` Ansible Collection includes the modules required to configure Chocolatey, as well as manage packages on Windows using Chocolatey.

## Ansible version compatibility

This collection has been tested against the following Ansible versions:
**>= 2.12, 2.13, 2.14**

## Installation and Usage

### Installing the Collection from Ansible Galaxy

Before using the Chocolatey collection, you need to install it with the `ansible-galaxy` CLI:

    ansible-galaxy collection install chocolatey.chocolatey

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml` using the format:

```yaml
collections:
- name: chocolatey.chocolatey
```

### Modules

This collection provides the following modules you can use in your own roles:

| Name                          | Description                               |
|-------------------------------|-------------------------------------------|
|`win_chocolatey`               | Manage packages using chocolatey          |
|`win_chocolatey_config`        | Manage Chocolatey config settings         |
|`win_chocolatey_facts`         | Create a facts collection for Chocolatey  |
|`win_chocolatey_feature`       | Manage Chocolatey features                |
|`win_chocolatey_source`        | Manage Chocolatey sources                 |

### Examples

Some example usages of the modules in this collection are below.

Upgrade all packages with Chocolatey:

```yaml
- name: Upgrade installed packages
  win_chocolatey:
    name: all
    state: latest
```

Install version 6.6 of `notepadplusplus`:

```yaml
- name: Install notepadplusplus version 6.6
  win_chocolatey:
    name: notepadplusplus
    version: '6.6'
```

Set the Chocolatey cache location:

```yaml
- name: Set the cache location
  win_chocolatey_config:
    name: cacheLocation
    state: present
    value: C:\Temp
```

Use Background Mode for Self-Service (Business Feature):

```yaml
- name: Use background mode for self-service
  win_chocolatey_feature:
    name: useBackgroundService
    state: enabled
```

Remove the Community Package Repository (as you have an internal repository; recommended):

```yaml
- name: Disable Community Repo
  win_chocolatey_source:
    name: chocolatey
    state: absent
```

## Testing and Development

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

### Testing with `ansible-test`

The `tests` directory contains configuration for running integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the collection's test suites with the commands:

```code
ansible-test windows-integration --docker -v --color
```

## License

GPL v3.0 License

See [LICENSE](LICENSE) to see full text.

<!-- Link Targets -->

[pipeline-link]: https://dev.azure.com/ChocolateyCI/Chocolatey-Ansible/_build/latest?definitionId=2&branchName=master
[pipeline-badge]: https://dev.azure.com/ChocolateyCI/Chocolatey-Ansible/_apis/build/status/Chocolatey%20Collection%20CI?branchName=master
