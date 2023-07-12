#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#            Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#            Rohit Kumar <rohit.kumar6@ibm.com>
#            Sudheesh Reddy Satti<Sudheesh.Reddy.Satti@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_host
short_description: This module manages hosts on IBM Spectrum Virtualize family storage systems
version_added: "1.0.0"
description:
  - Ansible interface to manage 'mkhost', 'chhost', and 'rmhost' host commands.
options:
    name:
        description:
            - Specifies a name or label for the new host object.
        required: true
        type: str
    state:
        description:
            - Creates or updates (C(present)) or removes (C(absent)) a host.
        choices: [ absent, present ]
        required: true
        type: str
    clustername:
        description:
            - The hostname or management IP of the Spectrum Virtualize storage system.
        required: true
        type: str
    domain:
        description:
            - Domain for the Spectrum Virtualize storage system.
            - Valid when hostname is used for the parameter I(clustername).
        type: str
    username:
        description:
            - REST API username for the Spectrum Virtualize storage system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    password:
        description:
            - REST API password for the Spectrum Virtualize storage system.
            - The parameters I(username) and I(password) are required if not using I(token) to authenticate a user.
        type: str
    token:
        description:
            - The authentication token to verify a user on the Spectrum Virtualize storage system.
            - To generate a token, use the M(ibm.spectrum_virtualize.ibm_svc_auth) module.
        type: str
        version_added: '1.5.0'
    fcwwpn:
        description:
            - List of Initiator WWPNs to be added to the host. The complete list of WWPNs must be provided.
            - The parameters I(fcwwpn) and I(iscsiname) are mutually exclusive.
            - Required when I(state=present), to create or modify a Fibre Channel (FC) host.
        type: str
    iscsiname:
        description:
            - List of Initiator IQNs to be added to the host. IQNs are separated by comma. The complete list of IQNs must be provided.
            - The parameters I(fcwwpn) and I(iscsiname) are mutually exclusive.
            - Valid when I(state=present), to create host.
        type: str
    iogrp:
        description:
            - Specifies a set of one or more input/output (I/O) groups from which the host can access the volumes.
              Once specified, this parameter cannot be modified.
            - Valid when I(state=present), to create a host.
        type: str
    nqn:
        description:
           - List of initiator NQNs to be added to the host. Each NQN is separated by a comma. The complete list of NQNs must be provided.
           - Required when I(protocol=rdmanvme), to create.
           - Valid when I(state=present), to create or modify a host.
        type: str
        version_added: '1.12.0'
    protocol:
        description:
            - Specifies the protocol used by the host to communicate with the storage system. Only 'scsi' protocol is supported.
            - Valid when I(state=present), to create a host.
        choices: [scsi, rdmanvme ]
        type: str
    type:
        description:
            - Specifies the type of host.
            - Valid when I(state=present), to create or modify a host.
        type: str
    site:
        description:
            - Specifies the site name of the host.
            - Valid when I(state=present), to create or modify a host.
        type: str
    hostcluster:
        description:
            - Specifies the name of the host cluster to which the host object is to be added.
              A host cluster must exist before a host object can be added to it.
            - Parameters I(hostcluster) and I(nohostcluster) are mutually exclusive.
            - Valid when I(state=present), to create or modify a host.
        type: str
        version_added: '1.5.0'
    nohostcluster:
        description:
            - If specified as C(True), host object is removed from the host cluster.
            - Parameters I(hostcluster) and I(nohostcluster) are mutually exclusive.
            - Valid when I(state=present), to modify an existing host.
        type: bool
        version_added: '1.5.0'
    old_name:
        description:
            - Specifies the old name of the host while renaming.
            - Valid when I(state=present), to rename an existing host.
        type: str
        version_added: '1.9.0'
    portset:
       description:
           - Specifies the portset to be associated with the host.
           - Valid when I(state=present), to create or modify a host.
       type : str
       version_added: '1.12.0'
    log_path:
        description:
            - Path of debug log file.
        type: str
    validate_certs:
        description:
            - Validates certification.
        default: false
        type: bool
author:
    - Sreshtant Bohidar (@Sreshtant-Bohidar)
    - Rohit Kumar (@rohitk-github)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Define a new iSCSI host
  ibm.spectrum_virtualize.ibm_svc_host:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: host4test
    state: present
    iscsiname: iqn.1994-05.com.redhat:2e358e438b8a
    iogrp: 0:1:2:3
    protocol: scsi
    type: generic
    site: site-name
    portset: portset0
- name: Add a host to an existing host cluster
  ibm.spectrum_virtualize.ibm_svc_host:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: host4test
    state: present
    hostcluster: hostcluster0
- name: Define a new FC host
  ibm.spectrum_virtualize.ibm_svc_host:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: host4test
    state: present
    fcwwpn: 100000109B570216:1000001AA0570266
    iogrp: 0:1:2:3
    protocol: scsi
    type: generic
    site: site-name
- name: Rename an existing host
  ibm.spectrum_virtualize.ibm_svc_host:
    clustername: "{{ clustername }}"
    domain: "{{ domain }}"
    username: "{{ username }}"
    password: "{{ password }}"
    old_name: "host4test"
    name: "new_host_name"
    state: "present"
- name: Create an iSCSI host
  ibm.spectrum_virtualize.ibm_svc_host:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: host_name
    iscsiname: iqn.1994-05.com.redhat:2e358e438b8a,iqn.localhost.hostid.7f000001
    state: present
- name: Delete a host
  ibm.spectrum_virtualize.ibm_svc_host:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: new_host_name
    state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.spectrum_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVChost(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                fcwwpn=dict(type='str', required=False),
                iscsiname=dict(type='str', required=False),
                iogrp=dict(type='str', required=False),
                protocol=dict(type='str', required=False, choices=['scsi',
                                                                   'rdmanvme']),
                type=dict(type='str'),
                site=dict(type='str'),
                hostcluster=dict(type='str'),
                nohostcluster=dict(type='bool'),
                old_name=dict(type='str', required=False),
                nqn=dict(type='str', required=False),
                portset=dict(type='str', required=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional
        self.fcwwpn = self.module.params.get('fcwwpn', '')
        self.iscsiname = self.module.params.get('iscsiname', '')
        self.iogrp = self.module.params.get('iogrp', '')
        self.protocol = self.module.params.get('protocol', '')
        self.type = self.module.params.get('type', '')
        self.site = self.module.params.get('site', '')
        self.hostcluster = self.module.params.get('hostcluster', '')
        self.nohostcluster = self.module.params.get('nohostcluster', '')
        self.old_name = self.module.params.get('old_name', '')
        self.nqn = self.module.params.get('nqn', '')
        self.portset = self.module.params.get('portset', '')

        self.basic_checks()

        # internal variable
        self.changed = False

        # Handling duplicate fcwwpn
        if self.fcwwpn:
            dup_fcwwpn = self.duplicate_checker(self.fcwwpn.split(':'))
            if dup_fcwwpn:
                self.module.fail_json(msg='The parameter {0} has been entered multiple times. Enter the parameter only one time.'.format(dup_fcwwpn))

        # Handling duplicate iscsiname
        if self.iscsiname:
            dup_iscsiname = self.duplicate_checker(self.iscsiname.split(','))
            if dup_iscsiname:
                self.module.fail_json(msg='The parameter {0} has been entered multiple times. Enter the parameter only one time.'.format(dup_iscsiname))

        # Handling duplicate nqn
        if self.nqn:
            dup_nqn = self.duplicate_checker(self.nqn.split(','))
            if dup_nqn:
                self.module.fail_json(
                    msg='The parameter {0} has been entered multiple times. Enter the parameter only one time.'.format(
                        dup_nqn))

        # Handling for missing mandatory parameter name
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')
        # Handling for parameter protocol
        if self.protocol:
            if self.protocol not in ('scsi', 'rdmanvme'):
                self.module.fail_json(msg="[{0}] is not supported for iscsiname. only 'scsi' and 'rdmanvme' "
                                          "protocol is supported.".format(self.protocol))

        self.restapi = IBMSVCRestApi(
            module=self.module,
            clustername=self.module.params['clustername'],
            domain=self.module.params['domain'],
            username=self.module.params['username'],
            password=self.module.params['password'],
            validate_certs=self.module.params['validate_certs'],
            log_path=log_path,
            token=self.module.params['token']
        )

    def basic_checks(self):
        if self.state == 'absent':
            fields = [f for f in ['protocol', 'portset', 'nqn', 'type'] if getattr(self, f)]

            if any(fields):
                self.module.fail_json(msg='Parameters {0} not supported while deleting a host'.format(', '.join(fields)))

    # for validating parameter while renaming a volume
    def parameter_handling_while_renaming(self):
        parameters = {
            "fcwwpn": self.fcwwpn,
            "iscsiname": self.iscsiname,
            "iogrp": self.iogrp,
            "protocol": self.protocol,
            "type": self.type,
            "site": self.site,
            "hostcluster": self.hostcluster,
            "nohostcluster": self.nohostcluster
        }
        parameters_exists = [parameter for parameter, value in parameters.items() if value]
        if parameters_exists:
            self.module.fail_json(msg="Parameters {0} not supported while renaming a host.".format(parameters_exists))

    def duplicate_checker(self, items):
        unique_items = set(items)
        if len(items) != len(unique_items):
            return [element for element in unique_items if items.count(element) > 1]
        else:
            return []

    def get_existing_host(self, host_name):
        merged_result = {}

        data = self.restapi.svc_obj_info(cmd='lshost', cmdopts=None,
                                         cmdargs=[host_name])

        if isinstance(data, list):
            for d in data:
                merged_result.update(d)
        else:
            merged_result = data

        return merged_result

    # TBD: Implement a more generic way to check for properties to modify.
    def host_probe(self, data):
        props = []
        if self.hostcluster and self.nohostcluster:
            self.module.fail_json(msg="You must not pass in both hostcluster and "
                                      "nohostcluster to the module.")

        if self.hostcluster and (self.hostcluster != data['host_cluster_name']):
            if data['host_cluster_name'] != '':
                self.module.fail_json(msg="Host already belongs to hostcluster [%s]" % data['host_cluster_name'])
            else:
                props += ['hostcluster']

        # TBD: The parameter is fcwwpn but the view has fcwwpn label.
        if self.type:
            if self.type != data['type']:
                props += ['type']

        if self.fcwwpn:
            self.existing_fcwwpn = [node["WWPN"] for node in data['nodes'] if "WWPN" in node]
            self.input_fcwwpn = self.fcwwpn.upper().split(":")
            if set(self.existing_fcwwpn).symmetric_difference(set(self.input_fcwwpn)):
                props += ['fcwwpn']

        if self.iscsiname:
            self.existing_iscsiname = [node["iscsi_name"] for node in data['nodes'] if "iscsi_name" in node]
            self.input_iscsiname = self.iscsiname.split(",")
            if set(self.existing_iscsiname).symmetric_difference(set(self.input_iscsiname)):
                props += ['iscsiname']

        if self.nqn:
            self.existing_nqn = [node["nqn"] for node in data['nodes'] if "nqn" in node]
            self.input_nqn = self.nqn.split(",")
            if set(self.existing_nqn).symmetric_difference(set(self.input_nqn)):
                props += ['nqn']

        if self.site:
            if self.site != data['site_name']:
                props += ['site']

        if self.nohostcluster:
            if data['host_cluster_name'] != '':
                props += ['nohostcluster']

        if self.portset:
            if self.portset != data['portset_name']:
                props += ['portset']

        self.log("host_probe props='%s'", props)
        return props

    def host_create(self):
        if (not self.fcwwpn) and (not self.iscsiname) and (not self.nqn):
            self.module.fail_json(msg="You must pass in fcwwpn or iscsiname or nqn "
                                      "to the module.")

        if (self.fcwwpn and self.iscsiname) or (self.nqn and self.iscsiname) or (self.fcwwpn and self.nqn):
            self.module.fail_json(msg="You have to pass only one parameter among fcwwpn, nqn and "
                                      "iscsiname to the module.")

        if self.hostcluster and self.nohostcluster:
            self.module.fail_json(msg="You must not pass in both hostcluster and "
                                      "nohostcluster to the module.")

        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating host '%s'", self.name)

        # Make command
        cmd = 'mkhost'
        cmdopts = {'name': self.name, 'force': True}
        if self.fcwwpn:
            cmdopts['fcwwpn'] = self.fcwwpn
        elif self.iscsiname:
            cmdopts['iscsiname'] = self.iscsiname
        else:
            cmdopts['nqn'] = self.nqn

        cmdopts['protocol'] = self.protocol if self.protocol else 'scsi'
        if self.iogrp:
            cmdopts['iogrp'] = self.iogrp
        if self.type:
            cmdopts['type'] = self.type
        if self.site:
            cmdopts['site'] = self.site
        if self.portset:
            cmdopts['portset'] = self.portset

        self.log("creating host command '%s' opts '%s'",
                 self.fcwwpn, self.type)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create host result '%s'", result)

        if result and 'message' in result:
            self.changed = True
            self.log("create host result message '%s'", (result['message']))
        else:
            self.module.fail_json(
                msg="Failed to create host [%s]" % self.name)

    def host_fcwwpn_update(self):
        to_be_removed = ':'.join(list(set(self.existing_fcwwpn) - set(self.input_fcwwpn)))
        if to_be_removed:
            self.restapi.svc_run_command(
                'rmhostport',
                {'fcwwpn': to_be_removed, 'force': True},
                [self.name]
            )
            self.log('%s removed from %s', to_be_removed, self.name)
        to_be_added = ':'.join(list(set(self.input_fcwwpn) - set(self.existing_fcwwpn)))
        if to_be_added:
            self.restapi.svc_run_command(
                'addhostport',
                {'fcwwpn': to_be_added, 'force': True},
                [self.name]
            )
            self.log('%s added to %s', to_be_added, self.name)

    def host_iscsiname_update(self):
        to_be_removed = ','.join(list(set(self.existing_iscsiname) - set(self.input_iscsiname)))
        if to_be_removed:
            self.restapi.svc_run_command(
                'rmhostport',
                {'iscsiname': to_be_removed, 'force': True},
                [self.name]
            )
            self.log('%s removed from %s', to_be_removed, self.name)
        to_be_added = ','.join(list(set(self.input_iscsiname) - set(self.existing_iscsiname)))
        if to_be_added:
            self.restapi.svc_run_command(
                'addhostport',
                {'iscsiname': to_be_added, 'force': True},
                [self.name]
            )
            self.log('%s added to %s', to_be_added, self.name)

    def host_nqn_update(self):
        to_be_removed = ','.join(list(set(self.existing_nqn) - set(self.input_nqn)))
        if to_be_removed:
            self.restapi.svc_run_command(
                'rmhostport',
                {'nqn': to_be_removed, 'force': True},
                [self.name]
            )
            self.log('%s removed from %s', to_be_removed, self.name)
        to_be_added = ','.join(list(set(self.input_nqn) - set(self.existing_nqn)))
        if to_be_added:
            self.restapi.svc_run_command(
                'addhostport',
                {'nqn': to_be_added, 'force': True},
                [self.name]
            )
            self.log('%s added to %s', to_be_added, self.name)

    def host_update(self, modify, host_data):
        # update the host
        self.log("updating host '%s'", self.name)
        if 'hostcluster' in modify:
            self.addhostcluster()
        elif 'nohostcluster' in modify:
            self.removehostcluster(host_data)

        cmd = 'chhost'
        cmdopts = {}
        if 'fcwwpn' in modify:
            self.host_fcwwpn_update()
            self.changed = True
            self.log("fcwwpn of %s updated", self.name)
        if 'iscsiname' in modify:
            self.host_iscsiname_update()
            self.changed = True
            self.log("iscsiname of %s updated", self.name)
        if 'nqn' in modify:
            self.host_nqn_update()
            self.changed = True
            self.log("nqn of %s updated", self.name)
        if 'type' in modify:
            cmdopts['type'] = self.type
        if 'site' in modify:
            cmdopts['site'] = self.site
        if 'portset' in modify:
            cmdopts['portset'] = self.portset
        if cmdopts:
            cmdargs = [self.name]
            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
            # Any error will have been raised in svc_run_command
            # chhost does not output anything when successful.
            self.changed = True
            self.log("type of %s updated", self.name)

    def host_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting host '%s'", self.name)

        cmd = 'rmhost'
        cmdopts = {}
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chhost does not output anything when successful.
        self.changed = True

    def get_existing_hostcluster(self):
        self.log("get_existing_hostcluster %s", self.hostcluster)

        data = self.restapi.svc_obj_info(cmd='lshostcluster', cmdopts=None,
                                         cmdargs=[self.hostcluster])

        return data

    def addhostcluster(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("Adding host '%s' in hostcluster %s", self.name, self.hostcluster)

        cmd = 'addhostclustermember'
        cmdopts = {}
        cmdargs = [self.hostcluster]

        cmdopts['host'] = self.name

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chhost does not output anything when successful.
        self.changed = True

    def removehostcluster(self, data):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("removing host '%s' from hostcluster %s", self.name, data['host_cluster_name'])

        hostcluster_name = data['host_cluster_name']

        cmd = 'rmhostclustermember'
        cmdopts = {}
        cmdargs = [hostcluster_name]

        cmdopts['host'] = self.name
        cmdopts['keepmappings'] = True

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chhost does not output anything when successful.
        self.changed = True

    # function for renaming an existing host with a new name
    def host_rename(self, host_data):
        msg = ''
        self.parameter_handling_while_renaming()
        old_host_data = self.get_existing_host(self.old_name)
        if not old_host_data and not host_data:
            self.module.fail_json(msg="Host [{0}] does not exists.".format(self.old_name))
        elif old_host_data and host_data:
            self.module.fail_json(msg="Host [{0}] already exists.".format(self.name))
        elif not old_host_data and host_data:
            msg = "Host with name [{0}] already exists.".format(self.name)
        elif old_host_data and not host_data:
            # when check_mode is enabled
            if self.module.check_mode:
                self.changed = True
                return
            self.restapi.svc_run_command('chhost', {'name': self.name}, [self.old_name])
            self.changed = True
            msg = "Host [{0}] has been successfully rename to [{1}].".format(self.old_name, self.name)
        return msg

    def apply(self):
        changed = False
        msg = None
        modify = []

        host_data = self.get_existing_host(self.name)

        if self.state == 'present' and self.old_name:
            msg = self.host_rename(host_data)
        elif self.state == 'absent' and self.old_name:
            self.module.fail_json(msg="Rename functionality is not supported when 'state' is absent.")
        else:
            if host_data:
                if self.state == 'absent':
                    self.log("CHANGED: host exists, but requested state is 'absent'")
                    changed = True
                elif self.state == 'present':
                    # This is where we detect if chhost should be called
                    modify = self.host_probe(host_data)
                    if modify:
                        changed = True
            else:
                if self.state == 'present':
                    self.log("CHANGED: host does not exist, but requested state is 'present'")
                    changed = True

            if changed:
                if self.state == 'present':
                    if self.hostcluster:
                        hc_data = self.get_existing_hostcluster()
                        if hc_data is None:
                            self.module.fail_json(msg="Host cluster must already exist before its usage in this module")
                        elif not host_data and hc_data:
                            self.host_create()
                            self.addhostcluster()
                            msg = "host %s has been created and added to hostcluster." % self.name
                    elif not host_data:
                        self.host_create()
                        msg = "host %s has been created." % self.name
                    if host_data and modify:
                        # This is where we would modify
                        self.host_update(modify, host_data)
                        msg = "host [%s] has been modified." % self.name
                elif self.state == 'absent':
                    self.host_delete()
                    msg = "host [%s] has been deleted." % self.name
            else:
                self.log("exiting with no changes")
                if self.state == 'absent':
                    msg = "host [%s] did not exist." % self.name
                else:
                    msg = "host [%s] already exists." % self.name
        if self.module.check_mode:
            msg = 'skipping changes due to check mode'

        self.module.exit_json(msg=msg, changed=self.changed)


def main():
    v = IBMSVChost()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
