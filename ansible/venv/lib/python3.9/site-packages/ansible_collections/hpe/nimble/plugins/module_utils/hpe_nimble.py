#!/usr/bin/env python

# Copyright 2020 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this
# file except in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
# OF ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# author Alok Ranjan (alok.ranjan2@hpe.com)

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import datetime
import uuid

__version__ = "1.1.0"


def is_null_or_empty(name):
    if type(name) is bool:
        return False
    if not name or name == "":
        return True
    return False


def get_unique_string(baseName):
    unique_string = baseName + datetime.datetime.now().strftime(
        "-%d-%m-%Y") + '-' + str(uuid.uuid1().time)
    # make sure the length is not more than 64 char as nimble array allows only up to 64 char
    unique_string = unique_string[:63]
    return unique_string


# remove arguments from kwargs which are by default none or empty
def remove_null_args(**kwargs):
    tosearch = kwargs.copy()
    for key, value in tosearch.items():
        # list can be empty in case of update. Hence we should not remove that arg
        if type(value) is not bool and type(value) is not list:
            if is_null_or_empty(value):
                kwargs.pop(key)
    return kwargs


def is_dict_item_present_on_server(server_list_of_dict, dict_to_check):

    if dict_to_check is None and server_list_of_dict is None:
        return True
    if len(dict_to_check) == 0:
        return False
    if type(server_list_of_dict) is not list:
        return False

    for server_dict in server_list_of_dict:
        if (dict_to_check.items() <= server_dict.items()) is True:
            return True
    return False


# remove unchanged item from kwargs by matching them with the data present in given object attrs
def remove_unchanged_or_null_args(server_resp, **kwargs):
    # Filter out null/empty arguments from the input
    params = remove_null_args(**kwargs)
    # check if server resp has attribute called attrs
    if hasattr(server_resp, "attrs") is False or type(server_resp.attrs) is not dict:
        return (params, params)

    params_to_search = params.copy()
    changed_attrs_dict = {}

    for key, value in params_to_search.items():
        # there could be a possibility that a user provided a wrong "key" name which is not at all present
        # in server resp.In that case get() will return None and hence will be added to list of changed_attrs.
        server_value = server_resp.attrs.get(key)

        if type(server_value) is list and type(value) is dict:
            if len(value) == 0:
                continue
            # we will land here if the user wants to update a metadata.
            # server return a list of metadata dictionary
            temp_server_metadata_dict = {}
            for server_entry in server_value:
                temp_server_metadata_dict[server_entry['key']] = server_entry['value']
            if (value.items() <= temp_server_metadata_dict.items()) is False:
                changed_attrs_dict[key] = value
            else:
                params.pop(key)

        elif type(server_value) is dict and type(value) is dict:
            if len(value) == 0:
                continue
            if (value.items() <= server_value.items()) is False:
                changed_attrs_dict[key] = value
            else:
                params.pop(key)

        elif type(server_value) is list and type(value) is list:
            found_changed_list = False
            if len(value) != len(server_value):
                changed_attrs_dict[key] = value
                continue
            # check if the list has dictionary to compare
            for entry_to_check in value:
                if type(entry_to_check) is dict:
                    if is_dict_item_present_on_server(server_value, entry_to_check) is True:
                        continue
                    # no need to further check for other keys as we already got one mismatch
                    changed_attrs_dict[key] = value
                    found_changed_list = True
                else:
                    if server_value.sort() != value.sort():
                        changed_attrs_dict[key] = value
                        found_changed_list = True
                break
            if found_changed_list is False:
                params.pop(key)

        elif server_value is None and type(value) is list:
            # this is a special case wherein the user has provided an empty list and
            # server already has null value for that list. in this case we should not add the
            # argument to changed_attrs_dict
            if len(value) == 0:
                # don't add empty list for update
                continue
            changed_attrs_dict[key] = value
        elif server_value != value:
            # This is a special key used to force any operation for object.
            # So, that is never updated as a server attribute.
            if key != "force":
                changed_attrs_dict[key] = value
        else:
            # remove this from param from dictionary as value is same and already present on server
            params.pop(key)
    return (changed_attrs_dict, params)


def basic_auth_arg_fields():

    fields = {
        "host": {
            "required": True,
            "type": "str"
        },
        "username": {
            "required": True,
            "type": "str"
        },
        "password": {
            "required": True,
            "type": "str",
            "no_log": True
        }
    }
    return fields


def get_vol_id(client_obj, vol_name):
    if is_null_or_empty(vol_name):
        return None
    else:
        resp = client_obj.volumes.get(name=vol_name)
        if resp is None:
            raise Exception(f"Invalid value for volume {vol_name}")
        return resp.attrs.get("id")


def get_volcoll_id(client_obj, volcoll_name):
    if is_null_or_empty(volcoll_name):
        return None
    else:
        resp = client_obj.volume_collections.get(name=volcoll_name)
        if resp is None:
            raise Exception(f"Invalid value for volcoll {volcoll_name}")
        return resp.attrs.get("id")


def get_owned_by_group_id(client_obj, owned_by_group_name):
    if is_null_or_empty(owned_by_group_name):
        return None
    else:
        resp = client_obj.groups.get(name=owned_by_group_name)
        if resp is None:
            raise Exception(f"Invalid value for owned by group {owned_by_group_name}")
        return resp.attrs.get("id")


def get_pool_id(client_obj, pool_name):
    if is_null_or_empty(pool_name):
        return None
    else:
        resp = client_obj.pools.get(name=pool_name)
        if resp is None:
            raise Exception(f"Invalid value for pool {pool_name}")
        return resp.attrs.get("id")


def get_folder_id(client_obj, folder_name):
    if is_null_or_empty(folder_name):
        return None
    else:
        resp = client_obj.folders.get(name=folder_name)
        if resp is None:
            raise Exception(f"Invalid value for folder {folder_name}")
        return resp.attrs.get("id")


def get_perfpolicy_id(client_obj, perfpolicy_name):
    if is_null_or_empty(perfpolicy_name):
        return None
    else:
        resp = client_obj.performance_policies.get(name=perfpolicy_name)
        if resp is None:
            raise Exception(f"Invalid value for performance policy: {perfpolicy_name}")
        return resp.attrs.get("id")


def get_prottmpl_id(client_obj, prottmpl_name):
    if is_null_or_empty(prottmpl_name):
        return None
    else:
        resp = client_obj.protection_templates.get(name=prottmpl_name)
        if resp is None:
            raise Exception(f"Invalid value for protection template {prottmpl_name}")
        return resp.attrs.get("id")


def get_chap_user_id(client_obj, chap_user_name):
    if is_null_or_empty(chap_user_name):
        return None
    else:
        resp = client_obj.chap_users.get(name=chap_user_name)
        if resp is None:
            raise Exception(f"Invalid value for chap user {chap_user_name}")
        return resp.attrs.get("id")


def get_pe_id(client_obj, pe_name):
    if is_null_or_empty(pe_name):
        return None
    else:
        resp = client_obj.protocol_endpoints.get(name=pe_name)
        if resp is None:
            raise Exception(f"Invalid value for protection endpoint {pe_name}")
        return resp.attrs.get("id")


def get_snapshot_id(client_obj, vol_name, snap_name):
    if is_null_or_empty(vol_name) or is_null_or_empty(snap_name):
        return None
    else:
        resp = client_obj.snapshots.get(vol_name=vol_name, name=snap_name)
        if resp is None:
            raise Exception(f"No snapshot with name '{snap_name}' found for volume {vol_name}.")
        return resp.attrs.get("id")


def get_replication_partner_id(client_obj, replication_partner_name):
    if is_null_or_empty(replication_partner_name):
        return None
    else:
        resp = client_obj.replication_partners.get(name=replication_partner_name)
        if resp is None:
            raise Exception(f"Invalid value for replication partner {replication_partner_name}")
        return resp.attrs.get("id")


def get_volcoll_or_prottmpl_id(client_obj, volcoll_name, prot_template_name):
    if is_null_or_empty(volcoll_name) and is_null_or_empty(prot_template_name):
        return None
    if is_null_or_empty(volcoll_name) is False and is_null_or_empty(prot_template_name) is False:
        raise Exception("Volcoll and prot_template are mutually exlusive. Please provide either one of them.")
    else:
        if volcoll_name is not None:
            resp = get_volcoll_id(client_obj, volcoll_name)
            if resp is None:
                raise Exception(f"Invalid value for volcoll: {volcoll_name}")
        elif prot_template_name is not None:
            resp = get_prottmpl_id(client_obj, prot_template_name)
            if resp is None:
                raise Exception(f"Invalid value for protection template {prot_template_name}")
        return resp


def get_downstream_partner_id(client_obj, downstream_partner):
    if is_null_or_empty(downstream_partner):
        return None
    else:
        resp = client_obj.replication_partners.get(name=downstream_partner)
        if resp is None:
            raise Exception(f"Invalid value for downstream partner {downstream_partner}")
        return resp.attrs.get("id")


def get_initiator_group_id(client_obj, ig_name):
    if is_null_or_empty(ig_name):
        return None
    else:
        resp = client_obj.initiator_groups.get(name=ig_name)
        if resp is None:
            raise Exception(f"Invalid value for initiator group {ig_name}")
        return resp.attrs.get("id")


def is_array_version_above_or_equal(array_obj_client, arr_version_to_check):
    if arr_version_to_check is None:
        return False
    resp = array_obj_client.get()
    if resp is None:
        return False
    array_version = resp.attrs.get("version")
    if array_version is None:
        return False

    temp = array_version.split('-')
    array_version = temp[0]
    arr_version = array_version.split('.')
    version_to_check = arr_version_to_check.split('.')
    if arr_version[0] > version_to_check[0]:
        return True
    elif arr_version[0] >= version_to_check[0] and arr_version[1] >= version_to_check[1]:
        return True
    elif arr_version[0] >= version_to_check[0] and arr_version[1] >= version_to_check[1] and arr_version[2] >= version_to_check[2]:
        return True
    return False
