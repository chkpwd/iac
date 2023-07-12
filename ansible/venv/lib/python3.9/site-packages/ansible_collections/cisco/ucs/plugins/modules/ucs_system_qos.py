#!/usr/bin/python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: ucs_system_qos
short_description: Configures system QoS settings
version_added: 2.10
description:
   -  Configures system QoS settings
extends_documentation_fragment: cisco.ucs.ucs
options:
    priority:
        description: Priority to configure
        choices: ["best-effort", "bronze", "fc", "gold","platinum", "silver"]
        required: true
    admin_state:
        description: Admin state of QoS Policy
        choices: ['disabled', 'enabled']
        default: enabled
    cos:
        description: CoS setting
        choices: ['any', '0-6']
        required: true
    weight:
        description: CoS profile weight
        choices: ['best-effort', 'none', '0-10']
        required: true
    mtu:
        description: MTU size
        choices: ['fc', 'normal', '0-4294967295']
        default: normal
    multicast_optimize:
        description: Set multicast optimization options
        choices: ['false', 'no', 'true', 'yes']
    drop:
        description: Set multicast optimization options
        default: 'drop'
        choices: ['drop', 'no-drop']
requirements: ['ucsmsdk']
author: "Brett Johnson (@sdbrett)"
'''

EXAMPLES = '''
- name:
  cisco.ucs.ucs_system_qos:
    priority: platinum
    admin_state: enabled
    multicast_optimize: no
    cos: '5'
    weight: '10'
    mtu: '9216'
    hostname: 192.168.99.100
    username: admin
    password: password
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.ucs.plugins.module_utils.ucs import UCSModule, ucs_argument_spec


# TODO Add ranges for cos, weight and mtu
def main():
    argument_spec = ucs_argument_spec
    argument_spec.update(
        priority=dict(required=True, type='str', choices=["best-effort", "bronze", "fc", "gold", "platinum", "silver"]),
        cos=dict(required=True, type='str'),
        weight=dict(required=True, type='str'),
        admin_state=dict(required=False, type='str', default='enabled', choices=['disabled', 'enabled']),
        drop=dict(required=False, type='str', default='drop', choices=['drop', 'no-drop']),
        mtu=dict(required=False, type='str', default='normal'),
        multicast_optimize=dict(required=False, type='str', default='no', choices=['false', 'no', 'true', 'yes']),
    )

    module = AnsibleModule(
        argument_spec,
        supports_check_mode=True,
    )
    ucs = UCSModule(module)

    err = False

    changed = False
    try:
        dn = "fabric/lan/classes/class-" + module.params['priority']
        mo = ucs.login_handle.query_dn(dn)
        # check top-level mo props
        if module.params['priority'] == 'best-effort':
            kwargs = dict(weight=module.params['weight'])
            kwargs['mtu'] = module.params['mtu']
            kwargs['multicast_optimize'] = module.params['multicast_optimize']
            if not mo.check_prop_match(**kwargs):
                if not module.check_mode:
                    mo.weight = module.params['weight']
                    mo.mtu = module.params['mtu']
                    mo.multicast_optimize = module.params['multicast_optimize']
                    ucs.login_handle.add_mo(mo, True)
                    ucs.login_handle.commit()
                changed = True
        elif module.params['priority'] == 'fc':
            kwargs = dict(weight=module.params['weight'])
            kwargs['cos'] = module.params['cos']
            if not mo.check_prop_match(**kwargs):
                if not module.check_mode:
                    mo.weight = module.params['weight']
                    mo.cos = module.params['cos']
                    ucs.login_handle.add_mo(mo, True)
                    ucs.login_handle.commit()
                changed = True

        else:
            kwargs = dict(weight=module.params['weight'])
            kwargs['priority'] = module.params['priority']
            kwargs['mtu'] = module.params['mtu']
            kwargs['cos'] = module.params['cos']
            kwargs['drop'] = module.params['drop']
            kwargs['admin_state'] = module.params['admin_state']
            kwargs['multicast_optimize'] = module.params['multicast_optimize']
        if not mo.check_prop_match(**kwargs):
            if not module.check_mode:
                mo.weight = module.params['weight']
                mo.mtu = module.params['mtu']
                mo.cos = module.params['cos']
                mo.drop = module.params['drop']
                mo.admin_state = module.params['admin_state']
                mo.multicast_optimize = module.params['multicast_optimize']

                ucs.login_handle.add_mo(mo, True)
                ucs.login_handle.commit()
            changed = True

    except Exception as e:
        err = True
        ucs.result['msg'] = "setup error: %s " % str(e)

    ucs.result['changed'] = changed
    if err:
        module.fail_json(**ucs.result)
    module.exit_json(**ucs.result)


if __name__ == '__main__':
    main()
