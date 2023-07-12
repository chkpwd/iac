# Ansible Icinga

This role is used to configure an Icinga Instance over its Icinga Director.

## Installation

* create a `requirements.yml`:

```bash
---
collections:
  - name: t_systems_mms.icinga_director
    src: https://github.com/T-Systems-MMS/ansible-collection-icinga-director
    version: 1.2.2
```

* install the collections:

```bash
ansible-galaxy collection install -r requirements.yml -p collections/
```

## Dependencies

collections:
t_systems_mms.icinga_director >= 1.2.2

## Role Variables

| Variable                         | Required | Default                     |
| -------------------------------- | -------- | --------------------------- |
| **icinga**                       |
| url                              | yes      |
| use_proxy                        | no       |
| validate_certs                   | no       |
| url_username                     | yes      |
| url_password                     | yes      |
| force_basic_auth                 | no       |
| client_cert                      | no       |
| client_key                       | no       |
| **icinga_timeperiod**            |
| icinga_timeperiods               | no       | []                          |
| display_name                     | no       |
| imports                          | no       |
| ranges                           | no       |
| **icinga_user_template**         |
| icinga_user_templates            | no       | []                          |
| imports                          | no       |
| period                           | no       |
| enable_notifications             | no       |
| **icinga_user**                  |
| icinga_users                     | no       | []                          |
| display_name                     | no       |
| imports                          | yes      | []                          |
| pager                            | no       |
| period                           | no       |
| disabled                         | no       |
| email                            | yes      | null                        |
| **icinga_zone**                  |
| icinga_zones                     | no       | []                          |
| is_global                        | no       |
| parent                           | no       |
| **icinga_endpoint**              |
| icinga_endpoints                 | no       | []                          |
| host                             | no       |
| port                             | no       |
| log_duration                     | no       |
| zone                             | no       |
| **icinga_hostgroup**             |
| icinga_hostgroups                | no       | []                          |
| display_name                     | no       |
| assign_filter                    | no       | `host.name="hostgroup.1-*"` |
| **icinga_host_template**         |
| icinga_host_templates            | no       | []                          |
| display_name                     | no       |
| address                          | no       |
| address6                         | no       |
| groups                           | no       |
| check_command                    | no       |
| check_interval                   | no       |
| disabled                         | no       |
| imports                          | no       |
| zone                             | no       |
| vars                             | no       |
| notes                            | no       |
| notes_url                        | no       |
| **icinga_host**                  |
| icinga_hosts                     | no       | []                          |
| display_name                     | no       |
| address                          | no       |
| address6                         | no       |
| groups                           | no       |
| disabled                         | no       |
| imports                          | yes      | []                          |
| zone                             | no       |
| vars                             | no       |
| notes                            | no       |
| notes_url                        | no       |
| **icinga_command_template**      |
| icinga_command_templates         | no       | []                          |
| display_name                     | no       |
| command                          | no       |
| methods_execute                  | yes      | PluginCheck                 |
| timeout                          | no       |
| imports                          | no       |
| disabled                         | no       |
| zone                             | no       |
| vars                             | no       |
| arguments                        | no       |
| **icinga_command**               |
| icinga_commands                  | no       | []                          |
| command_type                     | yes      | PluginCheck                 |
| disabled                         | yes      | false                       |
| imports                          | no       |
| zone                             | no       |
| vars                             | no       |
| **icinga_service**               |
| icinga_services                  | no       | []                          |
| display_name                     | no       |
| disabled                         | no       |
| check_command                    | no       |
| check_interval                   | no       |
| check_period                     | no       |
| check_timeout                    | no       |
| enable_active_checks             | no       |
| enable_event_handler             | no       |
| enable_notifications             | no       |
| enable_passive_checks            | no       |
| enable_perfdata                  | no       |
| groups                           | no       |
| host                             | yes      |
| imports                          | no       |
| max_check_attempts               | no       |
| notes                            | no       |
| notes_url                        | no       |
| retry_interval                   | no       |
| use_agent                        | no       |
| vars                             | no       |
| volatile                         | no       |
| **icinga_service_template**      |
| icinga_service_templates         | no       | []                          |
| display_name                     | no       |
| disabled                         | no       |
| check_command                    | no       |
| check_interval                   | no       |
| check_period                     | no       |
| check_timeout                    | no       |
| enable_active_checks             | no       |
| enable_event_handler             | no       |
| enable_notifications             | no       |
| enable_passive_checks            | no       |
| enable_perfdata                  | no       |
| groups                           | no       |
| imports                          | no       |
| max_check_attempts               | no       |
| notes                            | no       |
| notes_url                        | no       |
| retry_interval                   | no       |
| use_agent                        | no       |
| vars                             | no       |
| volatile                         | no       |
| **icinga_service_apply**         |
| icinga_service_applys            | no       | []                          |
| display_name                     | no       |
| groups                           | no       |
| apply_for                        | no       |
| assign_filter                    | no       |
| imports                          | no       |
| vars                             | no       |
| notes                            | no       |
| notes_url                        | no       |
| **icinga_servicegroup**          |
| icinga_servicegroups             | no       | []                          |
| display_name                     | no       |
| assign_filter                    | no       |
| **icinga_notification_template** |
| icinga_notification_templates    | no       | []                          |
| notification_template_object     | no       |
| state                            | no       |
| notification_interval            | no       |
| states                           | no       |
| types                            | no       |
| times_begin                      | no       |
| times_end                        | no       |
| timeperiod                       | no       |
| users                            | no       |
| user_groups                      | no       |
| notification_command             | no       |
| imports                          | no       |
| **icinga_notification**          |
| icinga_notifications             | no       | []                          |
| notification_interval            | no       |
| types                            | no       |
| users                            | no       |
| apply_to                         | no       |
| assign_filter                    | no       |
| imports                          | no       |
| period                           | no       |
| **icinga_scheduled_downtime**              |
| icinga_scheduled_downtimes                 | no       | []                                 |
| state                            | yes      | present
| disabled                         | no       | false
| assign_filter                    | no       |
| apply_to                         | yes      |
| author                           | yes      |
| comment                          | yes      |
| duration                         | no       |
| fixed                            | yes      |
| ranges                           | no       |
| with_services                    | no       | true

## Example Playbook

```bash
---
- hosts: localhost
  gather_facts: false
  collections:
  - t_systems_mms.icinga_director
  roles:
    - ansible_icinga
  vars:
    icinga_url: "https://example.com"
    icinga_user: "{{ icinga_user }}"
    icinga_pass: "{{ icinga_pass }}"
    icinga_timeperiods:
      - timeperiod_object:
        - "8x5"
        ranges:
          monday: "09:00-17:00"
          tuesday: "09:00-17:00"
          wednesday: "09:00-17:00"
          thursday: "09:00-17:00"
          friday: "09:00-17:00"
      - timeperiod_object:
        - "24x7"
        ranges:
          monday: "00:00-24:00"
          tuesday: "00:00-24:00"
          wednesday: "00:00-24:00"
          thursday: "00:00-24:00"
          friday: "00:00-24:00"
          saturday: "00:00-24:00"
          sunday: "00:00-24:00"
    icinga_users:
      - user_object:
        - "service_abbreviation_email_24x7"
        pager: "SIP/xxx"
        email: "service_abbreviation@example.com"
      - user_object:
        - "service_abbreviation_8x5"
        email: "service_abbreviation@example.com"
    icinga_hostgroups:
      - hostgroup_object:
        - "service_abbreviation-environement"
        - "service_abbreviation-environement-web"
    icinga_hosts:
      - host_object:
        - "service_abbreviation-environement-web01"
    icinga_scheduled_downtimes:
      - scheduled_downtime_object:
        - "service_abbreviation-environement-downtime01"
```
