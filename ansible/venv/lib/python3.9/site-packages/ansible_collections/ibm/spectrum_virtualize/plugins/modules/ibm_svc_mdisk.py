#!/usr/bin/python
# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_mdisk
short_description: This module manages MDisks on IBM Spectrum Virtualize family storage systems
description:
  - Ansible interface to manage 'mkarray' and 'rmmdisk' MDisk commands.
version_added: "1.0.0"
options:
  name:
    description:
      - The MDisk name.
    required: true
    type: str
  state:
    description:
      - Creates (C(present)) or removes (C(absent)) the MDisk.
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
    - To generate a token, use the ibm_svc_auth module.
    type: str
    version_added: '1.5.0'
  drive:
    description:
      - Drive(s) to use as members of the RAID array.
      - Required when I(state=present), to create an MDisk array.
    type: str
  mdiskgrp:
    description:
      - The storage pool (mdiskgrp) to which you want to add the MDisk.
    type: str
    required: true
  log_path:
    description:
      - Path of debug log file.
    type: str
  validate_certs:
    description:
      - Validates certification.
    default: false
    type: bool
  level:
    description:
      - Specifies the RAID level.
      - Required when I(state=present), to create an MDisk array.
    type: str
    choices: ['raid0', 'raid1', 'raid5', 'raid6', 'raid10']
  encrypt:
    description:
      - Defines use of encryption with the MDisk group.
      - Applies when I(state=present).
    type: str
    default: 'no'
    choices: ['yes', 'no']
author:
    - Peng Wang(@wangpww)
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Create MDisk and name as mdisk20
  ibm.spectrum_virtualize.ibm_svc_mdisk:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    name: mdisk20
    state: present
    level: raid0
    drive: '5:6'
    encrypt: no
    mdiskgrp: pool20
- name: Delete MDisk named mdisk20
  ibm.spectrum_virtualize.ibm_svc_mdisk:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    name: mdisk20
    state: absent
    mdiskgrp: pool20
'''

RETURN = '''#'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
from ansible_collections.ibm.spectrum_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger


class IBMSVCmdisk(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                name=dict(type='str', required=True),
                state=dict(type='str', required=True, choices=['absent',
                                                               'present']),
                level=dict(type='str', choices=['raid0', 'raid1', 'raid5',
                                                'raid6', 'raid10']),
                drive=dict(type='str', default=None),
                encrypt=dict(type='str', default='no', choices=['yes', 'no']),
                mdiskgrp=dict(type='str', required=True)
            )
        )

        mutually_exclusive = []
        self.module = AnsibleModule(argument_spec=argument_spec,
                                    mutually_exclusive=mutually_exclusive,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        # Required
        self.name = self.module.params['name']
        self.state = self.module.params['state']

        # Optional
        self.level = self.module.params.get('level', None)
        self.drive = self.module.params.get('drive', None)
        self.encrypt = self.module.params.get('encrypt', None)
        self.mdiskgrp = self.module.params.get('mdiskgrp', None)

        # Handling missing mandatory parameters name
        if not self.name:
            self.module.fail_json(msg='Missing mandatory parameter: name')

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

    def mdisk_exists(self):
        return self.restapi.svc_obj_info(cmd='lsmdisk', cmdopts=None,
                                         cmdargs=[self.name])

    def mdisk_create(self):
        # For now we create mdisk through mkarray which needs these options
        # level, drive, mdiskgrp
        if not self.level:
            self.module.fail_json(msg="You must pass in level to the module.")
        if not self.drive:
            self.module.fail_json(msg="You must pass in drive to the module.")
        if not self.mdiskgrp:
            self.module.fail_json(msg="You must pass in "
                                      "mdiskgrp to the module.")

        if self.module.check_mode:
            self.changed = True
            return

        self.log("creating mdisk '%s'", self.name)

        # Make command
        cmd = 'mkarray'
        cmdopts = {}
        if self.level:
            cmdopts['level'] = self.level
        if self.drive:
            cmdopts['drive'] = self.drive
        if self.encrypt:
            cmdopts['encrypt'] = self.encrypt
        cmdopts['name'] = self.name
        cmdargs = [self.mdiskgrp]
        self.log("creating mdisk command=%s opts=%s args=%s",
                 cmd, cmdopts, cmdargs)

        # Run command
        result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)
        self.log("create mdisk result %s", result)

        if 'message' in result:
            self.changed = True
            self.log("create mdisk result message %s", result['message'])
        else:
            self.module.fail_json(
                msg="Failed to create mdisk [%s]" % self.name)

    def mdisk_delete(self):
        if self.module.check_mode:
            self.changed = True
            return

        self.log("deleting mdisk '%s'", self.name)
        cmd = 'rmmdisk'
        cmdopts = {}
        cmdopts['mdisk'] = self.name
        cmdargs = [self.mdiskgrp]

        self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmkdiskgrp does not output anything when successful.
        self.changed = True

    def mdisk_update(self, modify):
        # update the mdisk
        self.log("updating mdisk '%s'", self.name)

        # cmd = 'chmdisk'
        # cmdopts = {}
        # chmdisk does not like mdisk arrays.
        # cmdargs = [self.name]

        # TBD: Implement changed logic.
        # result = self.restapi.svc_run_command(cmd, cmdopts, cmdargs)

        # Any error will have been raised in svc_run_command
        # chmkdiskgrp does not output anything when successful.
        self.changed = True

    # TBD: Implement a more generic way to check for properties to modify.
    def mdisk_probe(self, data):
        props = []

        if self.encrypt:
            if self.encrypt != data['encrypt']:
                props += ['encrypt']

        if props is []:
            props = None

        self.log("mdisk_probe props='%s'", data)
        return props

    def apply(self):
        changed = False
        msg = None
        modify = []

        mdisk_data = self.mdisk_exists()

        if mdisk_data:
            if self.state == 'absent':
                self.log("CHANGED: mdisk exists, but "
                         "requested state is 'absent'")
                changed = True
            elif self.state == 'present':
                # This is where we detect if chmdisk should be called.
                modify = self.mdisk_probe(mdisk_data)
                if modify:
                    changed = True
        else:
            if self.state == 'present':
                self.log("CHANGED: mdisk does not exist, "
                         "but requested state is 'present'")
                changed = True

        if changed:
            if self.state == 'present':
                if not mdisk_data:
                    self.mdisk_create()
                    msg = "Mdisk [%s] has been created." % self.name
                else:
                    # This is where we would modify
                    self.mdisk_update(modify)
                    msg = "Mdisk [%s] has been modified." % self.name
            elif self.state == 'absent':
                self.mdisk_delete()
                msg = "Volume [%s] has been deleted." % self.name

            if self.module.check_mode:
                msg = 'skipping changes due to check mode'
        else:
            self.log("exiting with no changes")
            if self.state == 'absent':
                msg = "Mdisk [%s] did not exist." % self.name
            else:
                msg = "Mdisk [%s] already exists." % self.name

        self.module.exit_json(msg=msg, changed=changed)


def main():
    v = IBMSVCmdisk()
    try:
        v.apply()
    except Exception as e:
        v.log("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
