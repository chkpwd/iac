#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2015 Nandaja Varma <nvarma@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
# USA.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
module: geo_rep
short_description: Manage geo-replication sessions
description:
  - Create, stop, delete and configure geo-replication session
author: Sachidananda Urs (@sac)
options:
  action:
    description:
      - Action to be performed on geo-replication session.
    required: true
    choices: ['create', 'start', 'stop', 'delete', 'pause', 'resume', 'config']
    type: str
  mastervol:
    description:
      - Master volume name.
    type: str
  slavevol:
    description:
      - Slave volume name.
    type: str
  force:
    description:
      - force the system to perform the action.
    type: str
  georepuser:
    description:
      - Username to be used for the action being performed.
    type: str
  gluster_log_file:
    description:
      - The path to the geo-replication glusterfs log file.
    type: str
  gluster_log_level:
    description:
      - The log level for glusterfs processes.
    type: str
  log_file:
    description:
      - The path to the geo-replication log file.
    type: str
  log_level:
    description:
      - The log level for geo-replication.
    type: str
  changelog_log_level:
    description:
      - The log level for the changelog.
    type: str
  ssh_command:
    description:
      - The SSH command to connect to the remote machine.
    type: str
  rsync_command:
    description:
      - The command to use for setting synchronizing method for the files.
    type: str
  use_tarssh:
    description:
      - To use tar over ssh.
    type: str
  volume_id:
    description:
      - deletes the existing master UID for the intermediate/slave node.
    type: str
  timeout:
    description:
      - timeout period.
    type: str
  sync_jobs:
    description:
      - number of sync-jobs .
    type: str
  ignore_deletes:
    description:
      - file deletion on the master will not trigger a delete operation on the slave.
    type: str
  checkpoint:
    description:
      - Sets a checkpoint with the given option.
    type: str
  sync_acls:
    description:
      - Syncs acls to the Slave cluster.
    type: str
  sync_xattrs:
    description:
      - Syncs extended attributes to the Slave cluster.
    type: str
  log_rsync_performance:
    description:
      - for recording the rsync performance in log files.
    type: str
  rsync_options:
    description:
      - Additional options to rsync.
    type: str
  use_meta_volume:
    description:
      - to use meta volume in Geo-replication.
    type: str
  meta_volume_mnt:
    description:
      - The path of the meta volume mount point.
    type: str
"""

EXAMPLES = """
- name: Create the geo-rep session
  gluster.gluster.geo_rep:
    action: create
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    force: true
    georepuser: staff
- name: Starts the geo-rep session
  gluster.gluster.geo_rep:
    action: start
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    force: true
    georepuser: staff
- name: Pause the geo-rep session
  gluster.gluster.geo_rep:
    action: pause
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    force: true
    georepuser: staff
- name: Resume the geo-rep session
  gluster.gluster.geo_rep:
    action: resume
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    force: true
    georepuser: staff
- name: Stop the geo-rep session
  gluster.gluster.geo_rep:
    action: stop
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    force: true
    georepuser: staff
- name: Configures the geo-rep session
  gluster.gluster.geo_rep:
    action: config
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    gluster_log_file: /var/log/glusterfs/geo-replication/gluster.log
    gluster_log_level: INFO
    log_file: /var/log/glusterfs/geo-replication/file.log
    log_level: INFO
    changelog_log_level: INFO
    ssh_command: SSH
    rsync_command: rsync
    use_tarssh: true
    volume_id: 6a071cfa-b150-4f0b-b1ed-96ab5d4bd671
    timeout: 60
    sync_jobs: 3
    ignore_deletes: 1
    checkpoint: now
    sync_acls: true
    sync_xattr: true
    log_rsync_performance: true
    rsync_options: --compress-level=0
    use_meta_volume: true
    meta_volume_mnt: /var/run/gluster/shared_storage/
- name: Delete the geo-rep session
  gluster.gluster.geo_rep:
    action: delete
    mastervol: 10.70.42.122:mastervolume
    slavevol: 10.70.43.48:slavevolume
    georepuser: staff
"""

import re
from ansible.module_utils.basic import AnsibleModule


class GeoRep(object):
    def __init__(self, module):
        self.module = module
        self.action = self._validated_params('action')
        self.gluster_georep_ops()

    def get_playbook_params(self, opt):
        return self.module.params[opt]

    def _validated_params(self, opt):
        value = self.get_playbook_params(opt)
        if value is None:
            msg = "Please provide %s option in the playbook!" % opt
            self.module.fail_json(msg=msg)
        return value

    def gluster_georep_ops(self):
        mastervol = self._validated_params('mastervol')
        slavevol = self._validated_params('slavevol')
        slavevol = self.check_pool_exclusiveness(mastervol, slavevol)
        if self.action in ['delete', 'config']:
            force = ''
        else:
            force = self._validated_params('force')
            force = 'force' if force == 'yes' else ' '
        options = 'no-verify' if self.action == 'create' \
            else self.config_georep()
        if isinstance(options, list):
            for opt in options:
                rc, output, err = self.call_gluster_cmd('volume',
                                                        'geo-replication',
                                                        mastervol, slavevol,
                                                        self.action, opt,
                                                        force)
        else:
            rc, output, err = self.call_gluster_cmd('volume',
                                                    'geo-replication',
                                                    mastervol, slavevol,
                                                    self.action, options,
                                                    force)
        self._get_output(rc, output, err)
        if self.action in ['stop', 'delete'] and self.user == 'root':
            self.user = 'geoaccount'
            rc, output, err = self.call_gluster_cmd('volume', 'geo-replication',
                                                    mastervol, slavevol.replace(
                                                        'root', 'geoaccount'),
                                                    self.action, options, force)
            self._get_output(rc, output, err)

    def config_georep(self):
        if self.action != 'config':
            return ''
        options = ['gluster_log_file', 'gluster_log_level', 'log_file',
                   'log_level', 'changelog_log_level', 'ssh_command',
                   'rsync_command', 'use_tarssh', 'volume_id', 'timeout',
                   'sync_jobs', 'ignore_deletes', 'checkpoint', 'sync_acls',
                   'sync_xattrs', 'log_rsync_performance', 'rsync_options',
                   'use_meta_volume', 'meta_volume_mnt']
        configs = []
        for opt in options:
            value = self._validated_params(opt)
            if value:
                if value == 'reset':
                    configs.append("'!" + opt.replace('_', '-') + "'")
                configs.append(opt.replace('_', '-') + ' ' + value)
        if configs:
            return configs
        value = self._validated_params('config')
        op = self._validated_params('op')
        return value + ' ' + op

    def check_pool_exclusiveness(self, mastervol, slavevol):
        rc, output, err = self.module.run_command(
            "gluster pool list")
        peers_in_cluster = [line.split('\t')[1].strip() for
                            line in filter(None, output.split('\n')[1:])]
        val_group = re.search("(.*):(.*)", slavevol)
        if not val_group:
            self.module.fail_json(msg="Slave volume in Unknown format. "
                                  "Correct format: <hostname>:<volume name>")
        if val_group.group(1) in peers_in_cluster:
            self.module.fail_json(msg="slave volume is in the trusted "
                                  "storage pool of master")
        self.user = 'root' if self.module.params['georepuser'] is None \
            else self.module.params['georepuser']
        return self.user + '@' + val_group.group(1) + '::' + val_group.group(2)

    def call_gluster_cmd(self, *args, **kwargs):
        params = ' '.join(opt for opt in args)
        key_value_pair = ' '.join(' %s %s ' % (key, value)
                                  for key, value in kwargs)
        return self._run_command('gluster', ' ' + params + ' ' + key_value_pair)

    def _get_output(self, rc, output, err):
        carryon = True if self.action in ['stop',
                                          'delete', 'resume'] else False
        changed = 0 if (carryon and rc) else 1
        if self.action in ['stop', 'delete'] and (
                self.user == 'root' and changed == 0):
            return
        if not rc or carryon:
            self.module.exit_json(stdout=output, changed=changed)
        else:
            self.module.fail_json(msg=err)

    def _run_command(self, op, opts):
        cmd = self.module.get_bin_path(op, True) + opts
        return self.module.run_command(cmd)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            action=dict(required=True, choices=['create', 'start',
                                                'stop', 'delete', 'pause', 'resume', 'config']),
            mastervol=dict(),
            slavevol=dict(),
            force=dict(),
            georepuser=dict(),
            gluster_log_file=dict(),
            gluster_log_level=dict(),
            log_file=dict(),
            log_level=dict(),
            changelog_log_level=dict(),
            ssh_command=dict(),
            rsync_command=dict(),
            use_tarssh=dict(),
            volume_id=dict(),
            timeout=dict(),
            sync_jobs=dict(),
            ignore_deletes=dict(),
            checkpoint=dict(),
            sync_acls=dict(),
            sync_xattrs=dict(),
            log_rsync_performance=dict(),
            rsync_options=dict(),
            use_meta_volume=dict(),
            meta_volume_mnt=dict()
        ),
    )
    GeoRep(module)


if __name__ == "__main__":
    main()
