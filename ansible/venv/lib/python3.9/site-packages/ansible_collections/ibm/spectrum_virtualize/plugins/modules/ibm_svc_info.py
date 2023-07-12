#!/usr/bin/python
# Copyright (C) 2020 IBM CORPORATION
# Author(s): Peng Wang <wangpww@cn.ibm.com>
#            Sreshtant Bohidar <sreshtant.bohidar@ibm.com>
#            Sanjaikumaar M <sanjaikumaar.m@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
---
module: ibm_svc_info
short_description: This module gathers various information from the IBM Spectrum Virtualize family storage systems
version_added: "1.0.0"
description:
- Gathers the list of specified IBM Spectrum Virtualize family storage system
  entities. These include the list of nodes, pools, volumes, hosts,
  host clusters, FC ports, iSCSI ports, target port FC, FC consistgrp,
  vdiskcopy, I/O groups, FC map, FC connectivity, NVMe fabric,
  array, and system.
author:
- Peng Wang (@wangpww)
options:
  clustername:
    description:
    - The hostname or management IP of the
      Spectrum Virtualize storage system.
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
  log_path:
    description:
    - Path of debug log file.
    type: str
  validate_certs:
    description:
    - Validates certification.
    default: false
    type: bool
  objectname:
    description:
    - If specified, only the instance with the I(objectname) is returned. If not specified, all the instances are returned.
    type: str
  gather_subset:
    type: list
    elements: str
    description:
    - List of string variables to specify the Spectrum Virtualize entities
      for which information is required.
    - all - list of all Spectrum Virtualize entities
            supported by the module.
    - vol - lists information for VDisks.
    - pool - lists information for mdiskgrps.
    - node - lists information for nodes.
    - iog - lists information for I/O groups.
    - host - lists information for hosts.
    - hostvdiskmap - lists all VDisks mapped to host 'objectname'
    - vdiskhostmap - lists all hosts VDisk 'objectname' is mapped to
    - hc - lists information for host clusters.
    - fc - lists information for FC connectivity.
    - fcport - lists information for FC ports.
    - targetportfc - lists information for WWPN which is required to set up
                     FC zoning and to display the current failover status
                     of host I/O ports.
    - fcmap - lists information for FC maps.
    - rcrelationship - lists information for remote copy relationships.
    - fcconsistgrp - displays a concise list or a detailed
                     view of flash copy consistency groups.
    - rcconsistgrp - displays a concise list or a detailed
                     view of remote copy consistency groups.
    - iscsiport - lists information for iSCSI ports.
    - vdiskcopy - lists information for volume copy.
    - array - lists information for array MDisks.
    - system - displays the storage system information.
    - cloudaccount - lists all the configured cloud accounts.
    - cloudaccountusage - lists the usage information about the configured cloud storage accounts.
    - cloudimportcandidate - lists information about systems that have data that is stored in the cloud accounts.
    - ldapserver - lists the most recent details for all configured Lightweight Directory Access Protocol (LDAP) servers.
    - drive - lists the configuration information and drive vital product data (VPD).
    - user - lists all the users that are created on the system.
    - usergroup - lists the user groups that is created on the system.
    - ownershipgroup - displays the ownership groups that are available in the system.
    - partnership - lists all the clustered systems (systems) that are associated with the local system.
    - replicationpolicy - lists all the replication policies on the system.
    - cloudbackup - lists the volumes that have cloud snapshot enabled and volumes that have cloud snapshots in the cloud account.
    - cloudbackupgeneration - lists any volume snapshots available on the specified volume. I(objectname) is a mandatory parameter.
    - snapshotpolicy - lists all the snapshot policies on the system.
    - snapshotpolicyschedule - lists all snapshot schedules on the system.
    - volumegroup - lists all volume groups on the system.
    - volumegroupsnapshotpolicy - lists the snapshot policy attributes associated with a volume group on the system.
    - volumesnapshot - lists all volume snapshots.
    - dnsserver - lists the information for any Domain Name System (DNS) servers in the system.
    - systemcertificate - lists the information about the current system Secure Sockets Layer (SSL) certificate.
    - truststore - lists the current certificate stores.
    - sra - command to check both secure remote assistance status and the time of the last login.
    - syslogserver - lists the syslog servers that are configured on the clustered system.
    - emailserver - lists the email servers that are configured on the system.
    - emailuser - lists the Email event notification settings for all Email recipients,
                  an individual Email recipient, or a specified type (local or support) of an Email recipient.
    - provisioningpolicy - lists the provisioning policies available on the system.
    - volumegroupsnapshot - lists the snapshot objects available on the system.
    - callhome - displays the status of the Call Home information that is sent to a server in the Cloud.
    - ip - lists the currently configured IP addresses.
    - portset - lists the currently configured portset on the system.
    - safeguardedpolicy - lists the Safeguarded policies available on the system.
    - mdisk - displays a concise list or a detailed view of managed disks (MDisks) visible to the system.
    - safeguardedpolicyschedule - displays the Safeguarded backup schedule that is associated with Safeguarded policies.
    - eventlog - displays the concise view of system event log
    - enclosurestats - lists the most recent values (averaged) of all enclosure statistics.
    - enclosurestatshistory - lists the history values of all enclosure statistics including power consumed,
                              temperature in fahrenheit and temperature in celsius.
    choices: [vol, pool, node, iog, host, hostvdiskmap, vdiskhostmap, hc, fcport
              , iscsiport, fc, fcmap, fcconsistgrp, rcrelationship, rcconsistgrp
              , vdiskcopy, targetportfc, array, system, 'cloudaccount', 'cloudaccountusage',
               'ldapserver', 'drive', 'user', 'usergroup', 'ownershipgroup',
               'partnership', 'replicationpolicy', 'cloudbackup', 'enclosurestats',
               'cloudbackupgeneration', 'snapshotpolicy', 'snapshotpolicyschedule',
               'volumegroup', 'volumegroupsnapshotpolicy', 'volumesnapshot',
               'dnsserver', 'systemcertificate', 'sra', 'syslogserver', 'enclosurestatshistory',
               'emailserver', 'emailuser', 'provisioningpolicy', 'volumegroupsnapshot',
               'truststore', 'callhome', 'ip', 'portset', 'safeguardedpolicy',
               'mdisk', 'safeguardedpolicyschedule', 'cloudimportcandidate', 'eventlog', all]
    default: "all"
notes:
    - This module supports C(check_mode).
'''

EXAMPLES = '''
- name: Get volume info
  ibm.spectrum_virtualize.ibm_svc_info:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/ansible.log
    gather_subset: vol
- name: Get volume info
  ibm.spectrum_virtualize.ibm_svc_info:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/ansible.log
    objectname: volumename
    gather_subset: vol
- name: Get pool info
  ibm.spectrum_virtualize.ibm_svc_info:
    clustername: "{{clustername}}"
    domain: "{{domain}}"
    username: "{{username}}"
    password: "{{password}}"
    log_path: /tmp/ansible.log
    gather_subset: pool
'''

RETURN = '''
Array:
    description:
        - Data will be populated when I(gather_subset=array) or I(gather_subset=all)
        - Lists information for array MDisks
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CallHome:
    description:
        - Data will be populated when I(gather_subset=callhome) or I(gather_subset=all)
        - Displays the status of the Call Home information that is sent to a server in the Cloud
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudAccount:
    description:
        - Data will be populated when I(gather_subset=cloudaccount) or I(gather_subset=all)
        - Lists all the configured cloud accounts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudAccountUsage:
    description:
        - Data will be populated when I(gather_subset=cloudaccountusage) or I(gather_subset=all)
        - Lists the usage information about the configured cloud storage accounts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudBackup:
    description:
        - Data will be populated when I(gather_subset=cloudbackup) or I(gather_subset=all)
        - Lists the volumes that have cloud snapshot that enabled and volumes that have cloud snapshots in the cloud account
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudBackupGeneration:
    description:
        - Data will be populated when I(gather_subset=cloudbackupgeneration)
        - List any volume snapshots available on the specified volume
    returned: success
    type: list
    elements: dict
    sample: [{...}]
CloudImportCandidate:
    description:
        - Data will be populated when I(gather_subset=cloudimportcandidate) or I(gather_subset=all)
        - Lists information about systems that have data that is stored in the cloud accounts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
DnsServer:
    description:
        - Data will be populated when I(gather_subset=dnsserver) or I(gather_subset=all)
        - Lists the information for any Domain Name System (DNS) servers in the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Drive:
    description:
        - Data will be populated when I(gather_subset=drive) or I(gather_subset=all)
        - Lists the configuration information and drive vital product data (VPD)
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EmailServer:
    description:
        - Data will be populated when I(gather_subset=emailserver) or I(gather_subset=all)
        - Lists the Email servers that are configured on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EmailUser:
    description:
        - Data will be populated when I(gather_subset=emailuser) or I(gather_subset=all)
        - Lists the Email event notification settings for all Email recipients,
          an individual Email recipient, or a specified type (local or support) of Email recipient
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCConnectivitie:
    description:
        - Data will be populated when I(gather_subset=fc) or I(gather_subset=all)
        - Lists information for FC connectivity
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCConsistgrp:
    description:
        - Data will be populated when I(gather_subset=fcconsistgrp) or I(gather_subset=all)
        - Displays a concise list or a detailed view of flash copy consistency groups
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCMap:
    description:
        - Data will be populated when I(gather_subset=fcmap) or I(gather_subset=all)
        - Lists information for FC maps
    returned: success
    type: list
    elements: dict
    sample: [{...}]
FCPort:
    description:
        - Data will be populated when I(gather_subset=fcport) or I(gather_subset=all)
        - Lists information for FC ports
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Host:
    description:
        - Data will be populated when I(gather_subset=host) or I(gather_subset=all)
        - Lists information for hosts
    returned: success
    type: list
    elements: dict
    sample: [{...}]
HostCluster:
    description:
        - Data will be populated when I(gather_subset=hc) or I(gather_subset=all)
        - Lists information for host clusters
    returned: success
    type: list
    elements: dict
    sample: [{...}]
HostVdiskMap:
    description:
        - Data will be populated when I(gather_subset=hostvdiskmap) or I(gather_subset=all)
        - Lists all VDisks mapped to host 'objectname'
    returned: success
    type: list
    elements: dict
    sample: [{...}]
IOGroup:
    description:
        - Data will be populated when I(gather_subset=iog) or I(gather_subset=all)
        - Lists information for I/O groups
    returned: success
    type: list
    elements: dict
    sample: [{...}]
IP:
    description:
        - Data will be populated when I(gather_subset=ip) or I(gather_subset=all)
        - Lists the currently configured IP addresses
    returned: success
    type: list
    elements: dict
    sample: [{...}]
LdapServer:
    description:
        - Data will be populated when I(gather_subset=ldapserver) or I(gather_subset=all)
        - Lists the most recent details for all configured Lightweight Directory Access Protocol (LDAP) servers
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Mdisk:
    description:
        - Data will be populated when I(gather_subset=mdisk) or I(gather_subset=all)
        - Displays a concise list or a detailed view of managed disks (MDisks) visible to the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Node:
    description:
        - Data will be populated when I(gather_subset=node) or I(gather_subset=all)
        - Lists information for nodes
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Ownershipgroup:
    description:
        - Data will be populated when I(gather_subset=ownershipgroup) or I(gather_subset=all)
        - Displays the ownership groups that are available in the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Partnership:
    description:
        - Data will be populated when I(gather_subset=partnership) or I(gather_subset=all)
        - Lists all the clustered systems (systems) that are associated with the local system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Pool:
    description:
        - Data will be populated when I(gather_subset=pool) or I(gather_subset=all)
        - Lists information for mdiskgrps
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Portset:
    description:
        - Data will be populated when I(gather_subset=portset) or I(gather_subset=all)
        - Lists the currently configured portset on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
ProvisioningPolicy:
    description:
        - Data will be populated when I(gather_subset=provisioningpolicy) or I(gather_subset=all)
        - Lists the provisioning policies available on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
RCConsistgrp:
    description:
        - Data will be populated when I(gather_subset=rcconsistgrp) or I(gather_subset=all)
        - Displays a concise list or a detailed view of remote copy consistency groups
    returned: success
    type: list
    elements: dict
    sample: [{...}]
RemoteCopy:
    description:
        - Data will be populated when I(gather_subset=rcrelationship) or I(gather_subset=all)
        - Lists information for remote copy relationships
    returned: success
    type: list
    elements: dict
    sample: [{...}]
ReplicationPolicy:
    description:
        - Data will be populated when I(gather_subset=replicationpolicy) or I(gather_subset=all)
        - Lists all the replication policies on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SafeguardedPolicy:
    description:
        - Data will be populated when I(gather_subset=safeguardedpolicy) or I(gather_subset=all)
        - Lists the Safeguarded policies available on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SafeguardedSchedule:
    description:
        - Data will be populated when I(gather_subset=safeguardedpolicyschedule) or I(gather_subset=all)
        - Displays the Safeguarded backup schedule that is associated with Safeguarded policies
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SnapshotPolicy:
    description:
        - Data will be populated when I(gather_subset=snapshotpolicy) or I(gather_subset=all)
        - Lists all the snapshot policies on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SnapshotSchedule:
    description:
        - Data will be populated when I(gather_subset=snapshotpolicyschedule) or I(gather_subset=all)
        - Lists all snapshot schedules on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Sra:
    description:
        - Data will be populated when I(gather_subset=sra) or I(gather_subset=all)
        - Command to check both secure remote assistance status and the time of the last login
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SysLogServer:
    description:
        - Data will be populated when I(gather_subset=syslogserver) or I(gather_subset=all)
        - Lists the syslog servers that are configured on the clustered system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
System:
    description:
        - Data will be populated when I(gather_subset=system) or I(gather_subset=all)
        - Displays the storage system information
    returned: success
    type: list
    elements: dict
    sample: [{...}]
SystemCert:
    description:
        - Data will be populated when I(gather_subset=systemcertificate) or I(gather_subset=all)
        - Lists the information about the current system Secure Sockets Layer (SSL) certificate
    returned: success
    type: list
    elements: dict
    sample: [{...}]
TargetPortFC:
    description:
        - Data will be populated when I(gather_subset=targetportfc) or I(gather_subset=all)
        - Lists information for WWPN which is required to set up FC zoning and to display
          the current failover status of host I/O ports
    returned: success
    type: list
    elements: dict
    sample: [{...}]
TrustStore:
    description:
        - Data will be populated when I(gather_subset=truststore) or I(gather_subset=all)
        - Lists the current certificate stores
    returned: success
    type: list
    elements: dict
    sample: [{...}]
User:
    description:
        - Data will be populated when I(gather_subset=user) or I(gather_subset=all)
        - Lists all the users that are created on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
UserGrp:
    description:
        - Data will be populated when I(gather_subset=usergroup) or I(gather_subset=all)
        - Lists the user groups that is created on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VdiskCopy:
    description:
        - Data will be populated when I(gather_subset=vdiskcopy) or I(gather_subset=all)
        - Lists information for volume copy
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VdiskHostMap:
    description:
        - Data will be populated when I(gather_subset=vdiskhostmap) or I(gather_subset=all)
        - Lists all hosts the VDisk 'objectname' is mapped to
    returned: success
    type: list
    elements: dict
    sample: [{...}]
Volume:
    description:
        - Data will be populated when I(gather_subset=vol) or I(gather_subset=all)
        - Lists information for VDisks
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroup:
    description:
        - Data will be populated when I(gather_subset=volumegroup) or I(gather_subset=all)
        - Lists all volume groups on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroupSnapshot:
    description:
        - Data will be populated when I(gather_subset=volumegroupsnapshot) or I(gather_subset=all)
        - Lists the snapshot objects available on the system based on volume group
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeGroupSnapshotPolicy:
    description:
        - Data will be populated when I(gather_subset=volumegroupsnapshotpolicy) or I(gather_subset=all)
        - Lists view snapshot objects on the system
    returned: success
    type: list
    elements: dict
    sample: [{...}]
VolumeSnapshot:
    description:
        - Data will be populated when I(gather_subset=volumesnapshot) or I(gather_subset=all)
        - Lists all volume snapshots
    returned: success
    type: list
    elements: dict
    sample: [{...}]
iSCSIPort:
    description:
        - Data will be populated when I(gather_subset=iscsiport) or I(gather_subset=all)
        - Lists information for iSCSI ports
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EventLog:
    description:
        - Data will be populated when I(gather_subset=eventlog) or I(gather_subset=all)
        - Lists information about the system event log
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EnclosureStats:
    description:
        - Data will be populated when I(gather_subset=enclosurestats) or I(gather_subset=all)
        - Lists the most recent values (averaged) of all enclosure statistics.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
EnclosureStatsHistory:
    description:
        - Data will be populated when I(gather_subset=enclosurestatshistory) or I(gather_subset=all)
        - Lists the history values of all enclosure statistics including power consumed,
          temperature in fahrenheit and temperature in celsius.
    returned: success
    type: list
    elements: dict
    sample: [{...}]
'''

from traceback import format_exc
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.ibm.spectrum_virtualize.plugins.module_utils.ibm_svc_utils import IBMSVCRestApi, svc_argument_spec, get_logger
from ansible.module_utils._text import to_native


class IBMSVCGatherInfo(object):
    def __init__(self):
        argument_spec = svc_argument_spec()

        argument_spec.update(
            dict(
                objectname=dict(type='str'),
                gather_subset=dict(type='list', elements='str', required=False,
                                   default=['all'],
                                   choices=['vol',
                                            'pool',
                                            'node',
                                            'iog',
                                            'host',
                                            'hostvdiskmap',
                                            'vdiskhostmap',
                                            'hc',
                                            'fc',
                                            'fcport',
                                            'targetportfc',
                                            'iscsiport',
                                            'fcmap',
                                            'rcrelationship',
                                            'fcconsistgrp',
                                            'rcconsistgrp',
                                            'vdiskcopy',
                                            'array',
                                            'system',
                                            'cloudaccount',
                                            'cloudaccountusage',
                                            'cloudimportcandidate',
                                            'ldapserver',
                                            'drive',
                                            'user',
                                            'usergroup',
                                            'ownershipgroup',
                                            'partnership',
                                            'replicationpolicy',
                                            'cloudbackup',
                                            'cloudbackupgeneration',
                                            'snapshotpolicy',
                                            'snapshotpolicyschedule',
                                            'volumegroup',
                                            'volumegroupsnapshotpolicy',
                                            'volumesnapshot',
                                            'dnsserver',
                                            'systemcertificate',
                                            'truststore',
                                            'sra',
                                            'syslogserver',
                                            'emailserver',
                                            'emailuser',
                                            'provisioningpolicy',
                                            'volumegroupsnapshot',
                                            'callhome',
                                            'ip',
                                            'portset',
                                            'safeguardedpolicy',
                                            'mdisk',
                                            'safeguardedpolicyschedule',
                                            'eventlog',
                                            'enclosurestats',
                                            'enclosurestatshistory',
                                            'all'
                                            ]),
            )
        )

        self.module = AnsibleModule(argument_spec=argument_spec,
                                    supports_check_mode=True)

        # logging setup
        log_path = self.module.params['log_path']
        self.log = get_logger(self.__class__.__name__, log_path)
        self.objectname = self.module.params['objectname']

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

    def validate(self, subset):
        if not self.objectname:
            self.module.fail_json(msg='Following paramter is mandatory to execute {0}: objectname'.format(subset))

    @property
    def cloudbackupgeneration(self):
        return self.restapi.svc_obj_info(
            cmd='lsvolumebackupgeneration',
            cmdopts={'volume': self.objectname},
            cmdargs=None
        )

    @property
    def enclosurestatshistory(self):
        return self.restapi.svc_obj_info(
            cmd='lsenclosurestats',
            cmdopts={'history': 'power_w:temp_c:temp_f'},
            cmdargs=[self.objectname]
        )

    def get_list(self, subset, op_key, cmd, validate):
        try:
            if validate:
                self.validate(subset)
            output = {}
            exceptions = {'cloudbackupgeneration', 'enclosurestatshistory'}
            if subset in exceptions:
                output[op_key] = getattr(self, subset)
            else:
                cmdargs = [self.objectname] if self.objectname else None
                output[op_key] = self.restapi.svc_obj_info(cmd=cmd,
                                                           cmdopts=None,
                                                           cmdargs=cmdargs)
            self.log.info('Successfully listed %d %s info '
                          'from cluster %s', len(subset), subset,
                          self.module.params['clustername'])
            return output
        except Exception as e:
            msg = 'Get %s info from cluster %s failed with error %s ' % \
                  (subset, self.module.params['clustername'], str(e))
            self.log.error(msg)
            self.module.fail_json(msg=msg)

    def apply(self):
        subset = self.module.params['gather_subset']
        if self.objectname and len(subset) != 1:
            msg = ("objectname(%s) is specified while gather_subset(%s) is not "
                   "one of %s" % (self.objectname, self.subset, all))
            self.module.fail_json(msg=msg)
        if len(subset) == 0 or 'all' in subset:
            self.log.info("The default value for gather_subset is all")

        result = {
            'Volume': [],
            'Pool': [],
            'Node': [],
            'IOGroup': [],
            'Host': [],
            'HostVdiskMap': [],
            'VdiskHostMap': [],
            'HostCluster': [],
            'FCConnectivitie': [],
            'FCConsistgrp': [],
            'RCConsistgrp': [],
            'VdiskCopy': [],
            'FCPort': [],
            'TargetPortFC': [],
            'iSCSIPort': [],
            'FCMap': [],
            'RemoteCopy': [],
            'Array': [],
            'System': [],
            'CloudAccount': [],
            'CloudAccountUsage': [],
            'CloudImportCandidate': [],
            'LdapServer': [],
            'Drive': [],
            'User': [],
            'Partnership': [],
            'ReplicationPolicy': [],
            'SnapshotPolicy': [],
            'VolumeGroup': [],
            'SnapshotSchedule': [],
            'VolumeGroupSnapshotPolicy': [],
            'VolumeSnapshot': [],
            'DnsServer': [],
            'SystemCert': [],
            'TrustStore': [],
            'Sra': [],
            'SysLogServer': [],
            'UserGrp': [],
            'EmailServer': [],
            'EmailUser': [],
            'CloudBackup': [],
            'CloudBackupGeneration': [],
            'ProvisioningPolicy': [],
            'VolumeGroupSnapshot': [],
            'CallHome': [],
            'IP': [],
            'Ownershipgroup': [],
            'Portset': [],
            'SafeguardedPolicy': [],
            'Mdisk': [],
            'SafeguardedSchedule': [],
            'EventLog': []
        }

        cmd_mappings = {
            'vol': ('Volume', 'lsvdisk', False),
            'pool': ('Pool', 'lsmdiskgrp', False),
            'node': ('Node', 'lsnode', False),
            'iog': ('IOGroup', 'lsiogrp', False),
            'host': ('Host', 'lshost', False),
            'hostvdiskmap': ('HostVdiskMap', 'lshostvdiskmap', False),
            'vdiskhostmap': ('VdiskHostMap', 'lsvdiskhostmap', False),
            'hc': ('HostCluster', 'lshostcluster', False),
            'fc': ('FCConnectivitie', 'lsfabric', False),
            'fcport': ('FCPort', 'lsportfc', False),
            'iscsiport': ('iSCSIPort', 'lsportip', False),
            'fcmap': ('FCMap', 'lsfcmap', False),
            'rcrelationship': ('RemoteCopy', 'lsrcrelationship', False),
            'fcconsistgrp': ('FCConsistgrp', 'lsfcconsistgrp', False),
            'rcconsistgrp': ('RCConsistgrp', 'lsrcconsistgrp', False),
            'vdiskcopy': ('VdiskCopy', 'lsvdiskcopy', False),
            'targetportfc': ('TargetPortFC', 'lstargetportfc', False),
            'array': ('Array', 'lsarray', False),
            'system': ('System', 'lssystem', False),
            'cloudaccount': ('CloudAccount', 'lscloudaccount', False),
            'cloudaccountusage': ('CloudAccountUsage', 'lscloudaccountusage', False),
            'cloudimportcandidate': ('CloudImportCandidate', 'lscloudaccountimportcandidate', False),
            'ldapserver': ('LdapServer', 'lsldapserver', False),
            'drive': ('Drive', 'lsdrive', False),
            'user': ('User', 'lsuser', False),
            'usergroup': ('UserGrp', 'lsusergrp', False),
            'ownershipgroup': ('Ownershipgroup', 'lsownershipgroup', False),
            'partnership': ('Partnership', 'lspartnership', False),
            'replicationpolicy': ('ReplicationPolicy', 'lsreplicationpolicy', False),
            'cloudbackup': ('CloudBackup', 'lsvolumebackup', False),
            'cloudbackupgeneration': ('CloudBackupGeneration', 'lsvolumebackupgeneration', True),
            'snapshotpolicy': ('SnapshotPolicy', 'lssnapshotpolicy', False),
            'snapshotpolicyschedule': ('SnapshotSchedule', 'lssnapshotschedule', False),
            'volumegroup': ('VolumeGroup', 'lsvolumegroup', False),
            'volumegroupsnapshotpolicy': ('VolumeGroupSnapshotPolicy', 'lsvolumegroupsnapshotpolicy', False),
            'volumesnapshot': ('VolumeSnapshot', 'lsvolumesnapshot', False),
            'dnsserver': ('DnsServer', 'lsdnsserver', False),
            'systemcertificate': ('SystemCert', 'lssystemcert', False),
            'truststore': ('TrustStore', 'lstruststore', False),
            'sra': ('Sra', 'lssra', False),
            'syslogserver': ('SysLogServer', 'lssyslogserver', False),
            'emailserver': ('EmailServer', 'lsemailserver', False),
            'emailuser': ('EmailUser', 'lsemailuser', False),
            'provisioningpolicy': ('ProvisioningPolicy', 'lsprovisioningpolicy', False),
            'volumegroupsnapshot': ('VolumeGroupSnapshot', 'lsvolumegroupsnapshot', False),
            'callhome': ('CallHome', 'lscloudcallhome', False),
            'ip': ('IP', 'lsip', False),
            'portset': ('Portset', 'lsportset', False),
            'safeguardedpolicy': ('SafeguardedPolicy', 'lssafeguardedpolicy', False),
            'mdisk': ('Mdisk', 'lsmdisk', False),
            'safeguardedpolicyschedule': ('SafeguardedSchedule', 'lssafeguardedschedule', False),
            'eventlog': ('EventLog', 'lseventlog', False),
            'enclosurestats': ('EnclosureStats', 'lsenclosurestats', False),
            'enclosurestatshistory': ('EnclosureStatsHistory', 'lsenclosurestats -history power_w:temp_c:temp_f', True)
        }

        if subset == ['all']:
            current_set = cmd_mappings.keys()
        else:
            current_set = subset

        for key in current_set:
            value_tuple = cmd_mappings[key]
            if subset == ['all'] and value_tuple[2]:
                continue

            op = self.get_list(key, *value_tuple)
            result.update(op)

        self.module.exit_json(**result)


def main():
    v = IBMSVCGatherInfo()
    try:
        v.apply()
    except Exception as e:
        v.log.debug("Exception in apply(): \n%s", format_exc())
        v.module.fail_json(msg="Module failed. Error [%s]." % to_native(e))


if __name__ == '__main__':
    main()
