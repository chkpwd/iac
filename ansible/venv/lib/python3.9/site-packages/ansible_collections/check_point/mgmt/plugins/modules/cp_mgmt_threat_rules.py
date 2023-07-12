#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2022 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for cp_mgmt_threat_rules
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
module: cp_mgmt_threat_rules
short_description: Manages THREAT RULES resource module
description:
  - This resource module allows for addition, deletion, or modification of CP Threat Rules.
  - This resource module also takes care of gathering Threat Rules config facts
version_added: 4.1.0
options:
  config:
    description: A dictionary of ACCESS RULES options
    type: dict
    suboptions:
      position:
        description:
          - Position in the rulebase.
          - The use of values "top" and "bottom" may not be idempotent.
        type: str
      layer:
        description: Layer that the rule belongs to identified by the name or UID.
        type: str
      name:
        description: Rule name.
        type: str
      action:
        description: Action-the enforced profile.
        type: str
      destination:
        description: Collection of Network objects identified by the name or UID.
        type: list
        elements: str
      destination_negate:
        description: True if negate is set for destination.
        type: bool
      enabled:
        description: Enable/Disable the rule.
        type: bool
      install_on:
        description: Which Gateways identified by the name or UID to install the policy
          on.
        type: list
        elements: str
      protected_scope:
        description: Collection of objects defining Protected Scope identified by
          the name or UID.
        type: list
        elements: str
      protected_scope_negate:
        description: True if negate is set for Protected Scope.
        type: bool
      service:
        description: Collection of Network objects identified by the name or UID.
        type: list
        elements: str
      service_negate:
        description: True if negate is set for Service.
        type: bool
      source:
        description: Collection of Network objects identified by the name or UID.
        type: list
        elements: str
      source_negate:
        description: True if negate is set for source.
        type: bool
      track:
        description: Packet tracking.
        type: str
      track_settings:
        description: Threat rule track settings.
        type: dict
        suboptions:
          packet_capture:
            description: Packet capture.
            type: bool
      comments:
        description: Comments string.
        type: str
      details_level:
        description: The level of detail for some of the fields in the response can
          vary from showing only the UID value of the object to a fully detailed representation
          of the object.
        type: str
        choices:
        - uid
        - standard
        - full
      ignore_warnings:
        description: Apply changes ignoring warnings.
        type: bool
      ignore_errors:
        description: Apply changes ignoring errors. You won't be able to publish such
          a changes. If ignore-warnings flag was omitted - warnings will also be ignored.
        type: bool
      auto_publish_session:
        description:
          - Publish the current session if changes have been performed
            after task completes.
        type: bool
      version:
        description:
          - Version of checkpoint. If not given one, the latest version taken.
        type: str
  state:
    description:
    - The state the configuration should be left in
    - The state I(gathered) will get the module API configuration from the device
      and transform it into structured data in the format as per the module argspec
      and the value is returned in the I(gathered) key within the result.
    type: str
    choices:
    - merged
    - replaced
    - gathered
    - deleted
author: Ansible Team
"""

EXAMPLES = """

# Using MERGED state
# -------------------

- name: To Add Merge Threat-Rules config
  cp_mgmt_threat_rules:
    state: merged
    config:
      comments: This is the THREAT RULE
      install_on: Policy Targets
      layer: IPS
      name: First threat rule
      position: 1
      protected_scope: All_Internet
      track: None

# RUN output:
# -----------

# mgmt_threat_rules:
#   after:
#     action: Optimized
#     comments: This is the THREAT RULE
#     destination:
#     - Any
#     destination_negate: false
#     enabled: true
#     install_on:
#     - Policy Targets
#     layer: 90678011-1bcb-4296-8154-fa58c23ecf3b
#     name: First threat rule
#     protected_scope:
#     - All_Internet
#     protected_scope_negate: false
#     service:
#     - Any
#     service_negate: false
#     source:
#     - Any
#     source_negate: false
#     track: None
#     track_settings:
#       packet_capture: true
#   before: {}

# Using REPLACED state
# --------------------

- name: Replace Threat-rule config
  cp_mgmt_threat_rules:
    config:
      comments: This is the REPLACED THREAT RULE
      install_on: Policy Targets
      layer: IPS
      name: First threat rule
      position: 1
      protected_scope: All_Internet
      track_settings:
        packet_capture: false
    state: replaced

# RUN output:
# -----------

# mgmt_threat_rules:
#   after:
#     action: Optimized
#     comments: This is the REPLACED THREAT RULE
#     destination:
#     - Any
#     destination_negate: false
#     enabled: true
#     install_on:
#     - Policy Targets
#     layer: 90678011-1bcb-4296-8154-fa58c23ecf3b
#     name: First threat rule
#     protected_scope:
#     - All_Internet
#     protected_scope_negate: false
#     service:
#     - Any
#     service_negate: false
#     source:
#     - Any
#     source_negate: false
#     track: None
#     track_settings:
#       packet_capture: false
#   before:
#     action: Optimized
#     comments: This is the THREAT RULE
#     destination:
#     - Any
#     destination_negate: false
#     enabled: true
#     install_on:
#     - Policy Targets
#     layer: 90678011-1bcb-4296-8154-fa58c23ecf3b
#     name: First threat rule
#     protected_scope:
#     - All_Internet
#     protected_scope_negate: false
#     service:
#     - Any
#     service_negate: false
#     source:
#     - Any
#     source_negate: false
#     track: None
#     track_settings:
#       packet_capture: true

# Using GATHERED state
# --------------------

- name: To Gather threat-rule by Name
  cp_mgmt_threat_rules:
    config:
      layer: IPS
      name: First threat rule
    state: gathered

# RUN output:
# -----------

# gathered:
#   action: Optimized
#   comments: This is the THREAT RULE
#   destination:
#   - Any
#   destination_negate: false
#   domain: SMC User
#   enabled: true
#   install_on:
#   - Policy Targets
#   layer: 90678011-1bcb-4296-8154-fa58c23ecf3b
#   name: First threat rule
#   protected_scope:
#   - All_Internet
#   protected_scope_negate: false
#   service:
#   - Any
#   service_negate: false
#   source:
#   - Any
#   source_negate: false
#   track: None
#   track_settings:
#     packet_capture: true
#   uid: ef832f64-fbe0-4b4e-85b8-8420911c449f

# Using DELETED state
# -------------------

- name: Delete Threat-rule config by Name and Layer
  cp_mgmt_threat_rules:
    config:
      layer: IPS
      name: First threat rule
    state: deleted

# RUN output:
# -----------

# mgmt_threat_rules:
#   after: {}
#   before:
#     action: Optimized
#     comments: This is the THREAT RULE
#     destination:
#     - Any
#     destination_negate: false
#     enabled: true
#     install_on:
#     - Policy Targets
#     layer: 90678011-1bcb-4296-8154-fa58c23ecf3b
#     name: First threat rule
#     protected_scope:
#     - All_Internet
#     protected_scope_negate: false
#     service:
#     - Any
#     service_negate: false
#     source:
#     - Any
#     source_negate: false
#     track: None
#     track_settings:
#       packet_capture: true

"""

RETURN = """
before:
  description: The configuration prior to the module execution.
  returned: when state is I(merged), I(replaced), I(deleted)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
after:
  description: The resulting configuration after module execution.
  returned: when changed
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
gathered:
  description: Facts about the network resource gathered from the remote device as structured data.
  returned: when state is I(gathered)
  type: dict
  sample: >
    This output will always be in the same format as the
    module argspec.
"""
