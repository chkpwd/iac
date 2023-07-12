# -*- coding: utf-8 -*-

# Copyright (c) 2020 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r'''
options:
    sops_binary:
        description:
            - Path to the sops binary.
            - By default uses C(sops).
        type: path
        version_added: 1.0.0
    age_key:
        description:
            - One or more age private keys that can be used to decrypt encrypted files.
            - Will be set as the C(SOPS_AGE_KEY) environment variable when calling sops.
        type: str
        version_added: 1.4.0
    age_keyfile:
        description:
            - The file containing the age private keys that sops can use to decrypt
              encrypted files.
            - Will be set as the C(SOPS_AGE_KEY_FILE) environment variable when calling sops.
            - By default, sops looks for C(sops/age/keys.txt) inside your user configuration
              directory.
        type: path
        version_added: 1.4.0
    aws_profile:
        description:
            - The AWS profile to use for requests to AWS.
            - This corresponds to the sops C(--aws-profile) option.
        type: str
        version_added: 1.0.0
    aws_access_key_id:
        description:
            - The AWS access key ID to use for requests to AWS.
            - Sets the environment variable C(AWS_ACCESS_KEY_ID) for the sops call.
        type: str
        version_added: 1.0.0
    aws_secret_access_key:
        description:
            - The AWS secret access key to use for requests to AWS.
            - Sets the environment variable C(AWS_SECRET_ACCESS_KEY) for the sops call.
        type: str
        version_added: 1.0.0
    aws_session_token:
        description:
            - The AWS session token to use for requests to AWS.
            - Sets the environment variable C(AWS_SESSION_TOKEN) for the sops call.
        type: str
        version_added: 1.0.0
    config_path:
        description:
            - Path to the sops configuration file.
            - If not set, sops will recursively search for the config file starting at
              the file that is encrypted or decrypted.
            - This corresponds to the sops C(--config) option.
        type: path
        version_added: 1.0.0
    enable_local_keyservice:
        description:
            - Tell sops to use local key service.
            - This corresponds to the sops C(--enable-local-keyservice) option.
        type: bool
        default: false
        version_added: 1.0.0
    keyservice:
        description:
            - Specify key services to use next to the local one.
            - A key service must be specified in the form C(protocol://address), for
              example C(tcp://myserver.com:5000).
            - This corresponds to the sops C(--keyservice) option.
        type: list
        elements: str
        version_added: 1.0.0
'''

    ANSIBLE_VARIABLES = r'''
options:
    sops_binary:
        vars:
            - name: sops_binary
    age_key:
        vars:
            - name: sops_age_key
    age_keyfile:
        vars:
            - name: sops_age_keyfile
    aws_profile:
        vars:
            - name: sops_aws_profile
    aws_access_key_id:
        vars:
            - name: sops_aws_access_key_id
    aws_secret_access_key:
        vars:
            - name: sops_aws_secret_access_key
    aws_session_token:
        vars:
            - name: sops_session_token
            - name: sops_aws_session_token
              version_added: 1.2.0
    config_path:
        vars:
            - name: sops_config_path
    enable_local_keyservice:
        vars:
            - name: sops_enable_local_keyservice
    keyservice:
        vars:
            - name: sops_keyservice
'''

    ANSIBLE_ENV = r'''
options:
    sops_binary:
        env:
            - name: ANSIBLE_SOPS_BINARY
              version_added: 1.2.0
    age_key:
        env:
            - name: ANSIBLE_SOPS_AGE_KEY
    age_keyfile:
        env:
            - name: ANSIBLE_SOPS_AGE_KEYFILE
    aws_profile:
        env:
            - name: ANSIBLE_SOPS_AWS_PROFILE
              version_added: 1.2.0
    aws_access_key_id:
        env:
            - name: ANSIBLE_SOPS_AWS_ACCESS_KEY_ID
              version_added: 1.2.0
    aws_secret_access_key:
        env:
            - name: ANSIBLE_SOPS_AWS_SECRET_ACCESS_KEY
              version_added: 1.2.0
    aws_session_token:
        env:
            - name: ANSIBLE_SOPS_AWS_SESSION_TOKEN
              version_added: 1.2.0
    config_path:
        env:
            - name: ANSIBLE_SOPS_CONFIG_PATH
              version_added: 1.2.0
    enable_local_keyservice:
        env:
            - name: ANSIBLE_SOPS_ENABLE_LOCAL_KEYSERVICE
              version_added: 1.2.0
    keyservice:
        env:
            - name: ANSIBLE_SOPS_KEYSERVICE
              version_added: 1.2.0
'''

    ANSIBLE_INI = r'''
options:
    sops_binary:
        ini:
            - section: community.sops
              key: binary
              version_added: 1.2.0
    # We do not provide an INI key for
    #     age_key
    # to make sure that secrets cannot be provided in ansible.ini. Use environment variables or another mechanism for that.
    age_keyfile:
        ini:
            - section: community.sops
              key: age_keyfile
    aws_profile:
        ini:
            - section: community.sops
              key: aws_profile
              version_added: 1.2.0
    aws_access_key_id:
        ini:
            - section: community.sops
              key: aws_access_key_id
              version_added: 1.2.0
    # We do not provide an INI key for
    #     aws_secret_access_key
    # to make sure that secrets cannot be provided in ansible.ini. Use environment variables or another mechanism for that.
    aws_session_token:
        ini:
            - section: community.sops
              key: aws_session_token
              version_added: 1.2.0
    config_path:
        ini:
            - section: community.sops
              key: config_path
              version_added: 1.2.0
    enable_local_keyservice:
        ini:
            - section: community.sops
              key: enable_local_keyservice
              version_added: 1.2.0
    keyservice:
        ini:
            - section: community.sops
              key: keyservice
              version_added: 1.2.0
'''

    ENCRYPT_SPECIFIC = r'''
options:
    age:
        description:
            - Age fingerprints to use.
            - This corresponds to the sops C(--age) option.
        type: list
        elements: str
        version_added: 1.4.0
    kms:
        description:
            - List of KMS ARNs to use.
            - This corresponds to the sops C(--kms) option.
        type: list
        elements: str
        version_added: 1.0.0
    gcp_kms:
        description:
            - GCP KMS resource IDs to use.
            - This corresponds to the sops C(--gcp-kms) option.
        type: list
        elements: str
        version_added: 1.0.0
    azure_kv:
        description:
            - Azure Key Vault URLs to use.
            - This corresponds to the sops C(--azure-kv) option.
        type: list
        elements: str
        version_added: 1.0.0
    hc_vault_transit:
        description:
            - HashiCorp Vault key URIs to use.
            - For example, C(https://vault.example.org:8200/v1/transit/keys/dev).
            - This corresponds to the sops C(--hc-vault-transit) option.
        type: list
        elements: str
        version_added: 1.0.0
    pgp:
        description:
            - PGP fingerprints to use.
            - This corresponds to the sops C(--pgp) option.
        type: list
        elements: str
        version_added: 1.0.0
    unencrypted_suffix:
        description:
            - Override the unencrypted key suffix.
            - This corresponds to the sops C(--unencrypted-suffix) option.
        type: str
        version_added: 1.0.0
    encrypted_suffix:
        description:
            - Override the encrypted key suffix.
            - When set to an empty string, all keys will be encrypted that are not explicitly
              marked by I(unencrypted_suffix).
            - This corresponds to the sops C(--encrypted-suffix) option.
        type: str
        version_added: 1.0.0
    unencrypted_regex:
        description:
            - Set the unencrypted key suffix.
            - When specified, only keys matching the regular expression will be left unencrypted.
            - This corresponds to the sops C(--unencrypted-regex) option.
        type: str
        version_added: 1.0.0
    encrypted_regex:
        description:
            - Set the encrypted key suffix.
            - When specified, only keys matching the regular expression will be encrypted.
            - This corresponds to the sops C(--encrypted-regex) option.
        type: str
        version_added: 1.0.0
    encryption_context:
        description:
            - List of KMS encryption context pairs of format C(key:value).
            - This corresponds to the sops C(--encryption-context) option.
        type: list
        elements: str
        version_added: 1.0.0
    shamir_secret_sharing_threshold:
        description:
            - The number of distinct keys required to retrieve the data key with
              L(Shamir's Secret Sharing, https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing).
            - If not set here and in the sops config file, will default to C(0).
            - This corresponds to the sops C(--shamir-secret-sharing-threshold) option.
        type: int
        version_added: 1.0.0
'''
