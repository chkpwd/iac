#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2016 IBM
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: role_assignment
short_description: Assign OpenStack identity groups and users to roles
author: OpenStack Ansible SIG
description:
  - Grant and revoke roles in either project or domain context for
    OpenStack identity (Keystone) users and groups.
options:
  domain:
    description:
      - Name or ID of the domain to scope the role association to.
      - Valid only with keystone version 3.
      - Required if I(project) is not specified.
      - When I(project) is specified, then I(domain) will not be used for
        scoping the role association, only for finding resources.
      - "When scoping the role association, I(project) has precedence over
         I(domain) and I(domain) has precedence over I(system): When I(project)
         is specified, then I(domain) and I(system) are not used for role
         association. When I(domain) is specified, then I(system) will not be
         used for role association."
    type: str
  group:
    description:
      - Name or ID for the group.
      - Valid only with keystone version 3.
      - If I(group) is not specified, then I(user) is required. Both may not be
        specified at the same time.
    type: str
  project:
    description:
      - Name or ID of the project to scope the role association to.
      - If you are using keystone version 2, then this value is required.
      - When I(project) is specified, then I(domain) will not be used for
        scoping the role association, only for finding resources.
      - "When scoping the role association, I(project) has precedence over
         I(domain) and I(domain) has precedence over I(system): When I(project)
         is specified, then I(domain) and I(system) are not used for role
         association. When I(domain) is specified, then I(system) will not be
         used for role association."
    type: str
  role:
    description:
      - Name or ID for the role.
    required: true
    type: str
  state:
    description:
      - Should the roles be present or absent on the user.
    choices: [present, absent]
    default: present
    type: str
  system:
    description:
      - Name of system to scope the role association to.
      - Valid only with keystone version 3.
      - Required if I(project) and I(domain) are not specified.
      - "When scoping the role association, I(project) has precedence over
         I(domain) and I(domain) has precedence over I(system): When I(project)
         is specified, then I(domain) and I(system) are not used for role
         association. When I(domain) is specified, then I(system) will not be
         used for role association."
    type: str
  user:
    description:
      - Name or ID for the user.
      - If I(user) is not specified, then I(group) is required. Both may not be
        specified at the same time.
    type: str
extends_documentation_fragment:
  - openstack.cloud.openstack
'''

EXAMPLES = r'''
- name: Grant an admin role on the user admin in the project project1
  openstack.cloud.role_assignment:
    cloud: mycloud
    user: admin
    role: admin
    project: project1

- name: Revoke the admin role from the user barney in the newyork domain
  openstack.cloud.role_assignment:
    cloud: mycloud
    state: absent
    user: barney
    role: admin
    domain: newyork
'''

from ansible_collections.openstack.cloud.plugins.module_utils.openstack import OpenStackModule


class IdentityRoleAssignmentModule(OpenStackModule):
    argument_spec = dict(
        domain=dict(),
        group=dict(),
        project=dict(),
        role=dict(required=True),
        state=dict(default='present', choices=['absent', 'present']),
        system=dict(),
        user=dict(),
    )

    module_kwargs = dict(
        required_one_of=[
            ('user', 'group'),
            ('domain', 'project', 'system'),
        ],
        supports_check_mode=True
    )

    def run(self):
        filters = {}
        find_filters = {}
        kwargs = {}

        role_name_or_id = self.params['role']
        role = self.conn.identity.find_role(role_name_or_id,
                                            ignore_missing=False)
        filters['role_id'] = role['id']

        domain_name_or_id = self.params['domain']
        if domain_name_or_id is not None:
            domain = self.conn.identity.find_domain(
                domain_name_or_id, ignore_missing=False)
            filters['scope_domain_id'] = domain['id']
            find_filters['domain_id'] = domain['id']
            kwargs['domain'] = domain['id']

        user_name_or_id = self.params['user']
        if user_name_or_id is not None:
            user = self.conn.identity.find_user(
                user_name_or_id, ignore_missing=False, **find_filters)
            filters['user_id'] = user['id']
            kwargs['user'] = user['id']

        group_name_or_id = self.params['group']
        if group_name_or_id is not None:
            group = self.conn.identity.find_group(
                group_name_or_id, ignore_missing=False, **find_filters)
            filters['group_id'] = group['id']
            kwargs['group'] = group['id']

        system_name = self.params['system']
        if system_name is not None:
            # domain has precedence over system
            if 'scope_domain_id' not in filters:
                filters['scope.system'] = system_name

            kwargs['system'] = system_name

        project_name_or_id = self.params['project']
        if project_name_or_id is not None:
            project = self.conn.identity.find_project(
                project_name_or_id, ignore_missing=False, **find_filters)
            filters['scope_project_id'] = project['id']
            kwargs['project'] = project['id']

            # project has precedence over domain and system
            filters.pop('scope_domain_id', None)
            filters.pop('scope.system', None)

        role_assignments = list(self.conn.identity.role_assignments(**filters))

        state = self.params['state']
        if self.ansible.check_mode:
            self.exit_json(
                changed=((state == 'present' and not role_assignments)
                         or (state == 'absent' and role_assignments)))

        if state == 'present' and not role_assignments:
            self.conn.grant_role(role['id'], **kwargs)
            self.exit_json(changed=True)
        elif state == 'absent' and role_assignments:
            self.conn.revoke_role(role['id'], **kwargs)
            self.exit_json(changed=True)
        else:
            self.exit_json(changed=False)


def main():
    module = IdentityRoleAssignmentModule()
    module()


if __name__ == '__main__':
    main()
