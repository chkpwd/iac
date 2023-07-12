#!/usr/bin/python

# (c) 2017, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""Element OS Software Volume Manager"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'certified'}


DOCUMENTATION = '''

module: na_elementsw_volume

short_description: NetApp Element Software Manage Volumes
extends_documentation_fragment:
    - netapp.elementsw.netapp.solidfire
version_added: 2.7.0
author: NetApp Ansible Team (@carchi8py) <ng-ansibleteam@netapp.com>
description:
- Create, destroy, or update volumes on ElementSW

options:

    state:
        description:
        - Whether the specified volume should exist or not.
        choices: ['present', 'absent']
        default: present
        type: str

    name:
        description:
        - The name of the volume to manage.
        - It accepts volume_name or volume_id
        required: true
        type: str

    account_id:
        description:
        - Account ID for the owner of this volume.
        - It accepts Account_id or Account_name
        required: true
        type: str

    enable512e:
        description:
        - Required when C(state=present)
        - Should the volume provide 512-byte sector emulation?
        type: bool
        aliases:
        - enable512emulation

    qos:
        description: Initial quality of service settings for this volume. Configure as dict in playbooks.
        type: dict

    qos_policy_name:
        description:
            - Quality of service policy for this volume.
            - It can be a name or an id.
            - Mutually exclusive with C(qos) option.
        type: str

    attributes:
        description: A YAML dictionary of attributes that you would like to apply on this volume.
        type: dict

    size:
        description:
        - The size of the volume in (size_unit).
        - Required when C(state = present).
        type: int

    size_unit:
        description:
        - The unit used to interpret the size parameter.
        choices: ['bytes', 'b', 'kb', 'mb', 'gb', 'tb', 'pb', 'eb', 'zb', 'yb']
        default: 'gb'
        type: str

    access:
        description:
        - Access allowed for the volume.
        - readOnly           Only read operations are allowed.
        - readWrite          Reads and writes are allowed.
        - locked             No reads or writes are allowed.
        - replicationTarget  Identify a volume as the target volume for a paired set of volumes.
        - If the volume is not paired, the access status is locked.
        - If unspecified, the access settings of the clone will be the same as the source.
        choices: ['readOnly', 'readWrite', 'locked', 'replicationTarget']
        type: str
'''

EXAMPLES = """
   - name: Create Volume
     na_elementsw_volume:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: present
       name: AnsibleVol
       qos: {minIOPS: 1000, maxIOPS: 20000, burstIOPS: 50000}
       account_id: 3
       enable512e: False
       size: 1
       size_unit: gb

   - name: Update Volume
     na_elementsw_volume:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: present
       name: AnsibleVol
       account_id: 3
       access: readWrite

   - name: Delete Volume
     na_elementsw_volume:
       hostname: "{{ elementsw_hostname }}"
       username: "{{ elementsw_username }}"
       password: "{{ elementsw_password }}"
       state: absent
       name: AnsibleVol
       account_id: 2
"""

RETURN = """

msg:
    description: Success message
    returned: success
    type: str

"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_native
import ansible_collections.netapp.elementsw.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.elementsw.plugins.module_utils.netapp_elementsw_module import NaElementSWModule

HAS_SF_SDK = netapp_utils.has_sf_sdk()
try:
    import solidfire.common
except ImportError:
    HAS_SF_SDK = False


class ElementSWVolume(object):
    """
    Contains methods to parse arguments,
    derive details of  ElementSW objects
    and send requests to ElementOS via
    the ElementSW SDK
    """

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check paramenters and ensure SDK is installed
        """
        self._size_unit_map = netapp_utils.SF_BYTE_MAP

        self.argument_spec = netapp_utils.ontap_sf_host_argument_spec()
        self.argument_spec.update(dict(
            state=dict(required=False, type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            account_id=dict(required=True),
            enable512e=dict(required=False, type='bool', aliases=['enable512emulation']),
            qos=dict(required=False, type='dict', default=None),
            qos_policy_name=dict(required=False, type='str', default=None),
            attributes=dict(required=False, type='dict', default=None),
            size=dict(type='int'),
            size_unit=dict(default='gb',
                           choices=['bytes', 'b', 'kb', 'mb', 'gb', 'tb',
                                    'pb', 'eb', 'zb', 'yb'], type='str'),

            access=dict(required=False, type='str', default=None,
                        choices=['readOnly', 'readWrite', 'locked', 'replicationTarget']),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            required_if=[
                ('state', 'present', ['size', 'enable512e'])
            ],
            mutually_exclusive=[
                ('qos', 'qos_policy_name'),
            ],
            supports_check_mode=True
        )

        param = self.module.params

        # set up state variables
        self.state = param['state']
        self.name = param['name']
        self.account_id = param['account_id']
        self.enable512e = param['enable512e']
        self.qos = param['qos']
        self.qos_policy_name = param['qos_policy_name']
        self.attributes = param['attributes']
        self.access = param['access']
        self.size_unit = param['size_unit']
        if param['size'] is not None:
            self.size = param['size'] * self._size_unit_map[self.size_unit]
        else:
            self.size = None

        if HAS_SF_SDK is False:
            self.module.fail_json(msg="Unable to import the ElementSW Python SDK")
        else:
            try:
                self.sfe = netapp_utils.create_sf_connection(module=self.module)
            except solidfire.common.ApiServerError:
                self.module.fail_json(msg="Unable to create the connection")

        self.elementsw_helper = NaElementSWModule(self.sfe)

        # add telemetry attributes
        if self.attributes is not None:
            self.attributes.update(self.elementsw_helper.set_element_attributes(source='na_elementsw_volume'))
        else:
            self.attributes = self.elementsw_helper.set_element_attributes(source='na_elementsw_volume')

    def get_account_id(self):
        """
            Return account id if found
        """
        try:
            # Update and return self.account_id
            self.account_id = self.elementsw_helper.account_exists(self.account_id)
        except Exception as err:
            self.module.fail_json(msg="Error: account_id %s does not exist" % self.account_id, exception=to_native(err))
        return self.account_id

    def get_qos_policy(self, name):
        """
        Get QOS Policy
        """
        policy, error = self.elementsw_helper.get_qos_policy(name)
        if error is not None:
            self.module.fail_json(msg=error)
        return policy

    def get_volume(self):
        """
            Return volume details if found
        """
        # Get volume details
        volume_id = self.elementsw_helper.volume_exists(self.name, self.account_id)

        if volume_id is not None:
            # Return volume_details
            volume_details = self.elementsw_helper.get_volume(volume_id)
            if volume_details is not None:
                return volume_details
        return None

    def create_volume(self, qos_policy_id):
        """
        Create Volume
        :return: True if created, False if fails
        """
        options = dict(
            name=self.name,
            account_id=self.account_id,
            total_size=self.size,
            enable512e=self.enable512e,
            attributes=self.attributes
        )
        if qos_policy_id is not None:
            options['qos_policy_id'] = qos_policy_id
        if self.qos is not None:
            options['qos'] = self.qos
        try:
            self.sfe.create_volume(**options)
        except Exception as err:
            self.module.fail_json(msg="Error provisioning volume: %s of size: %s" % (self.name, self.size),
                                  exception=to_native(err))

    def delete_volume(self, volume_id):
        """
         Delete and purge the volume using volume id
         :return: Success : True , Failed : False
        """
        try:
            self.sfe.delete_volume(volume_id=volume_id)
            self.sfe.purge_deleted_volume(volume_id=volume_id)
            # Delete method will delete and also purge the volume instead of moving the volume state to inactive.

        except Exception as err:
            # Throwing the exact error message instead of generic error message
            self.module.fail_json(msg='Error deleting volume: %s, %s' % (str(volume_id), to_native(err)),
                                  exception=to_native(err))

    def update_volume(self, volume_id, qos_policy_id):
        """
        Update the volume with the specified param
        :return: Success : True, Failed : False
        """
        options = dict(
            attributes=self.attributes
        )
        if self.access is not None:
            options['access'] = self.access
        if self.account_id is not None:
            options['account_id'] = self.account_id
        if self.qos is not None:
            options['qos'] = self.qos
        if qos_policy_id is not None:
            options['qos_policy_id'] = qos_policy_id
        if self.size is not None:
            options['total_size'] = self.size
        try:
            self.sfe.modify_volume(volume_id, **options)
        except Exception as err:
            # Throwing the exact error message instead of generic error message
            self.module.fail_json(msg='Error updating volume: %s, %s' % (str(volume_id), to_native(err)),
                                  exception=to_native(err))

    def apply(self):
        # Perform pre-checks, call functions and exit
        changed = False
        qos_policy_id = None
        action = None

        self.get_account_id()
        volume_detail = self.get_volume()

        if self.state == 'present' and self.qos_policy_name is not None:
            policy = self.get_qos_policy(self.qos_policy_name)
            if policy is None:
                error = 'Cannot find qos policy with name/id: %s' % self.qos_policy_name
                self.module.fail_json(msg=error)
            qos_policy_id = policy['qos_policy_id']

        if volume_detail:
            volume_id = volume_detail.volume_id
            if self.state == 'absent':
                action = 'delete'

            elif self.state == 'present':
                # Checking all the params for update operation
                if self.access is not None and volume_detail.access != self.access:
                    action = 'update'

                if self.account_id is not None and volume_detail.account_id != self.account_id:
                    action = 'update'

                if qos_policy_id is not None and volume_detail.qos_policy_id != qos_policy_id:
                    # volume_detail.qos_policy_id may be None if no policy is associated with the volume
                    action = 'update'

                if self.qos is not None and volume_detail.qos_policy_id is not None:
                    # remove qos_policy
                    action = 'update'

                if self.qos is not None:
                    # Actual volume_detail.qos has ['burst_iops', 'burst_time', 'curve', 'max_iops', 'min_iops'] keys.
                    # As only minOPS, maxOPS, burstOPS is important to consider, checking only these values.
                    volume_qos = vars(volume_detail.qos)
                    if volume_qos['min_iops'] != self.qos['minIOPS'] or volume_qos['max_iops'] != self.qos['maxIOPS'] \
                       or volume_qos['burst_iops'] != self.qos['burstIOPS']:
                        action = 'update'

                if self.size is not None and volume_detail.total_size is not None and volume_detail.total_size != self.size:
                    size_difference = abs(float(volume_detail.total_size - self.size))
                    # Change size only if difference is bigger than 0.001
                    if size_difference / self.size > 0.001:
                        action = 'update'

                if self.attributes is not None and volume_detail.attributes != self.attributes:
                    action = 'update'

        elif self.state == 'present':
            action = 'create'

        result_message = ""

        if action is not None:
            changed = True
            if self.module.check_mode:
                result_message = "Check mode, skipping changes"
            else:
                if action == 'create':
                    self.create_volume(qos_policy_id)
                    result_message = "Volume created"
                elif action == 'update':
                    self.update_volume(volume_id, qos_policy_id)
                    result_message = "Volume updated"
                elif action == 'delete':
                    self.delete_volume(volume_id)
                    result_message = "Volume deleted"

        self.module.exit_json(changed=changed, msg=result_message)


def main():
    # Create object and call apply
    na_elementsw_volume = ElementSWVolume()
    na_elementsw_volume.apply()


if __name__ == '__main__':
    main()
