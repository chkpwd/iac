#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#            Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#            Rohit kumar <rohit.kumar6@ibm.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_vdisk
short_description: This module manages volumes on IBM Spectrum Virtualize
                   Family storage systems
description:
  - Ansible interface to manage 'mkvdisk' and 'rmvdisk' volume commands.
version_added: "1.0.0"
options:
  name:
    description:
      - Specifies the name to assign to the new volume.
    required: true
    type: str
  state:
    description:
      - Creates (C(present)) or removes (C(absent)) a volume.
    choices: [ absent, present ]
    required: true
    type: str
  clustername:
    description:
    - The hostname or management IP of the Spectrum Virtualize storage system.
    type: str
    required: true
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
    - To generate a token, use ibm_svc_auth module.
    type: str
    version_added: '1.5.0'
  mdiskgrp:
    description:
    - Specifies the name of the storage pool to use when
      creating this volume. This parameter is required when I(state=present).
    type: str
  easytier:
    description:
    - Defines use of easytier with VDisk.
    - Applies when I(state=present).
    type: str
    choices: [ 'on', 'off' ]
  size:
    description:
    - Defines the size of VDisk. This parameter is required when I(state=present).
    - This parameter can also be used to resize an existing VDisk.
    type: str
  unit:
    description:
    - Defines the size option for the storage unit. This parameter is required when I(state=present).
    type: str
    choices: [ b, kb, mb, gb, tb, pb ]
    default: mb
  validate_certs:
    description:
    - Validates certification.
    default: false
    type: bool
  log_path:
    description:
    - Path of debug log file.
    type: str
  rsize:
    description:
    - Defines how much physical space is initially allocated to the thin-provisioned volume in %.
      If rsize is not passed, the volume created is a standard volume.
    - Applies when C(state=present).
    type: str
    version_added: '1.2.0'
  autoexpand:
    description:
    - Specifies that thin-provisioned volume copies can automatically expand their real capacities.
    type: bool
    version_added: '1.2.0'
author:
    - Sreshtant Bohidar(@Sreshtant-Bohidar)
    - Rohit Kumar(@rohitk-github)
notes:
    - This module supports C(check_mode).
deprecated:
  removed_in: 2.0.0
  why: New module released
  alternative: Use M(ibm.spectrum_virtualize.ibm_svc_manage_volume) instead.
'''

EXAMPLES = '''
- name: Create a volume
  ibm.spectrum_virtualize.ibm_svc_vdisk:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: volume0
    state: present
    mdiskgrp: Pool0
    easytier: 'off'
    size: "4294967296"
    unit: b
- name: Create a thin-provisioned volume
  ibm.spectrum_virtualize.ibm_svc_vdisk:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: volume0
    state: present
    mdiskgrp: Pool0
    easytier: 'off'
    size: "4294967296"
    unit: b
    rsize: '20%'
    autoexpand: true
- name: Delete a volume
  ibm.spectrum_virtualize.ibm_svc_vdisk:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/playbook.debug
    name: volume0
    state: absent
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.spectrum_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCvdisk(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                mdiskgrp=dict(type='str', required=False),
                size=dict(type='str', required=False),
                unit=dict(type='str', default='mb', choices=['b', 'kb',
                                                             'mb', 'gb',
                                                             'tb', 'pb']),
                easytier=dict(type='str', choices=['on', 'off']),
                rsize=dict(type='str', required=False),
                autoexpand=dict(type='bool', required=False)
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        self.resizevdisk_flag = False
        self.expand_flag = False
        self.shrink_flag = False

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional
        self.mdiskgrp = self.module.params['mdiskgrp']
        self.size = self.module.params['size']
        self.unit = self.module.params['unit']
        self.easytier = self.module.params.get('easytier', None)
        self.rsize = self.module.params['rsize']
        self.autoexpand = self.module.params['autoexpand']

        # Handling missing mandatory parameter name
        if not self.name:
            self.module.fail_json('Missing mandatory parameter: name')

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

    def convert_to_bytes(self):
        return int(self.size) * (1024 ** (['b', 'kb', 'mb', 'gb', 'tb', 'pb'].index((self.unit).lower())))

    def get_existing_vdisk(self):
        self.log("Entering function get_existing_vdisk")
        cmd = 'lsvdisk'
        cmdargs = {}
        cmdopts = {'bytes': True}
        cmdargs = [self.name]
        existing_vdisk_data = self.restapi.svc_obj_info(cmd, cmdopts, cmdargs)
        return existing_vdisk_data

    # TBD: Implement a more generic way to check for properties to modify.
    def vdisk_probe(self, data):
        props = []
        # Check if change in vdisk size is required
        input_size = int(self.convert_to_bytes())
        actual_size = int(data[0]['capacity'])
        if self.size:
            if input_size != actual_size:
                props += ['resize']
                if input_size > actual_size:
                    self.expand_flag = True
                    self.change_in_size = input_size - actual_size
                else:
                    self.shrink_flag = True
                    self.change_in_size = actual_size - input_size
        # TBD: The parameter is easytier but the view has easy_tier label.
        if self.easytier:
            if self.easytier != data[1]['easy_tier']:
                props += ['easytier']
        self.log("vdisk_probe props='%s'", props)
        return props

    def detect_vdisk_type(self, data):
        isMirrored = False
        if data[0]['type'] == "many":
            isMirrored = True
        if not isMirrored:
            relationship_name = data[0]['RC_name']
            if relationship_name:
                rel_data = self.restapi.svc_obj_info(cmd='lsrcrelationship', cmdopts=None, cmdargs=[relationship_name])
                if rel_data['copy_type'] == "activeactive":
                    isMirrored = True
        if isMirrored:
            self.module.fail_json(msg="Mirror volumes cannot be managed using this module.\
 To manage mirror volumes, module 'ibm_svc_manange_mirrored_volume' can be used")

    def resizevdisk(self):
        cmdopts = {}
        if self.expand_flag:
            cmd = "expandvdisksize"
        elif self.shrink_flag:
            cmd = "shrinkvdisksize"
        cmdopts["size"] = str(self.change_in_size)
        cmdopts["unit"] = "b"
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.changed = True

    def vdisk_create(self):
        if not self.mdiskgrp:
            self.module.fail_json(msg="You must pass in "
                                      "mdiskgrp to the module.")
        if not self.size:
            self.module.fail_json(msg="You must pass in size to the module.")
        if not self.unit:
            self.module.fail_json(msg="You must pass in unit to the module.")

        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating vdisk '%s'", self.name)

        # Make command
        cmd = 'mkvdisk'
        cmdopts = {}
        if self.mdiskgrp:
            cmdopts['mdiskgrp'] = self.mdiskgrp
        if self.size:
            cmdopts['size'] = self.size
        if self.unit:
            cmdopts['unit'] = self.unit
        if self.easytier:
            cmdopts['easytier'] = self.easytier
        if self.rsize:
            cmdopts['rsize'] = self.rsize
        if self.autoexpand:
            cmdopts['autoexpand'] = self.autoexpand
        cmdopts['name'] = self.name
        self.log("creating vdisk command %s opts %s", cmd, cmdopts)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs=None)
        self.log("create vdisk result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create vdisk result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create vdisk [%s]" % self.name)

    def vdisk_update(self, modify):
        self.log("updating vdisk '%s'", self.name)
        if 'resize' in modify and 'easytier' in modify:
            self.module.fail_json(msg="You cannot resize a volume while modifying other attributes")
        if self.module.check_mode:
            self.changed = True
            return
        if 'resize' in modify:
            self.resizevdisk()
            self.changed = True
        elif 'easytier' in modify:
            cmd = 'chvdisk'
            cmdopts = {}
            cmdopts['easytier'] = self.easytier
            cmdargs = [self.name]

            self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
            # Any error will have been raised in svc_run_command
            # chvdisk does not output anything when successful.
            self.changed = True

    def vdisk_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting vdisk '%s'", self.name)

        cmd = 'rmvdisk'
        cmdopts = None
        cmdargs = [self.name]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmvdisk does not output anything when successful.
        self.changed = True

    def apply(self):
        changed = False
        msg = None
        modify = []

        vdisk_data = self.get_existing_vdisk()
        if vdisk_data:
            self.detect_vdisk_type(vdisk_data)
            if self.state == 'absent':
                self.log("CHANGED: vdisk exists, but requested "
                         "state is 'absent'")
                changed = True
            elif self.state == 'present':
                # This is where we detect if chvdisk or resize should be called
                modify = self.vdisk_probe(vdisk_data)
                if modify:
                    changed = True
        else:
            if self.state == 'present':
                self.log("CHANGED: vdisk does not exist, "
                         "but requested state is 'present'")
                changed = True

        if changed:
            if self.state == 'present':
                if not vdisk_data:
                    self.vdisk_create()
                    msg = "vdisk [%s] has been created." % self.name
                else:
                    # This is where we would modify
                    self.vdisk_update(modify)
                    msg = "vdisk [%s] has been modified." % self.name
            elif self.state == 'absent':
                self.vdisk_delete()
                msg = "vdisk [%s] has been deleted." % self.name

            if self.module.check_mode:
                msg = 'skipping changes due to check mode'
        else:
            self.log("exiting with no changes")
            if self.state == 'absent':
                msg = "vdisk [%s] did not exist." % self.name
            else:
                msg = "vdisk [%s] already exists." % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCvdisk()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
