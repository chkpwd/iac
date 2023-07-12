#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type
from ansible.plugins.action import ActionBase

try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.ise.plugins.plugin_utils.ise import (
    ISESDK,
    ise_argument_spec,
    ise_compare_equality,
    get_dict_result,
)
from ansible_collections.cisco.ise.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = ise_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    authenticateBeforeCRLReceived=dict(type="bool"),
    automaticCRLUpdate=dict(type="bool"),
    automaticCRLUpdatePeriod=dict(type="int"),
    automaticCRLUpdateUnits=dict(type="str"),
    crlDistributionUrl=dict(type="str"),
    crlDownloadFailureRetries=dict(type="int"),
    crlDownloadFailureRetriesUnits=dict(type="str"),
    description=dict(type="str"),
    downloadCRL=dict(type="bool"),
    enableOCSPValidation=dict(type="bool"),
    enableServerIdentityCheck=dict(type="bool"),
    ignoreCRLExpiration=dict(type="bool"),
    name=dict(type="str"),
    nonAutomaticCRLUpdatePeriod=dict(type="int"),
    nonAutomaticCRLUpdateUnits=dict(type="str"),
    rejectIfNoStatusFromOCSP=dict(type="bool"),
    rejectIfUnreachableFromOCSP=dict(type="bool"),
    selectedOCSPService=dict(type="str"),
    status=dict(type="str"),
    trustForCertificateBasedAdminAuth=dict(type="bool"),
    trustForCiscoServicesAuth=dict(type="bool"),
    trustForClientAuth=dict(type="bool"),
    trustForIseAuth=dict(type="bool"),
    id=dict(type="str"),
))

required_if = [
    ("state", "present", ["id", "name"], True),
    ("state", "absent", ["id", "name"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class TrustedCertificate(object):
    def __init__(self, params, ise):
        self.ise = ise
        self.new_object = dict(
            authenticate_before_crl_received=params.get("authenticateBeforeCRLReceived"),
            automatic_crl_update=params.get("automaticCRLUpdate"),
            automatic_crl_update_period=params.get("automaticCRLUpdatePeriod"),
            automatic_crl_update_units=params.get("automaticCRLUpdateUnits"),
            crl_distribution_url=params.get("crlDistributionUrl"),
            crl_download_failure_retries=params.get("crlDownloadFailureRetries"),
            crl_download_failure_retries_units=params.get("crlDownloadFailureRetriesUnits"),
            description=params.get("description"),
            download_crl=params.get("downloadCRL"),
            enable_ocsp_validation=params.get("enableOCSPValidation"),
            enable_server_identity_check=params.get("enableServerIdentityCheck"),
            ignore_crl_expiration=params.get("ignoreCRLExpiration"),
            name=params.get("name"),
            non_automatic_crl_update_period=params.get("nonAutomaticCRLUpdatePeriod"),
            non_automatic_crl_update_units=params.get("nonAutomaticCRLUpdateUnits"),
            reject_if_no_status_from_ocs_p=params.get("rejectIfNoStatusFromOCSP"),
            reject_if_unreachable_from_ocs_p=params.get("rejectIfUnreachableFromOCSP"),
            selected_ocsp_service=params.get("selectedOCSPService"),
            status=params.get("status"),
            trust_for_certificate_based_admin_auth=params.get("trustForCertificateBasedAdminAuth"),
            trust_for_cisco_services_auth=params.get("trustForCiscoServicesAuth"),
            trust_for_client_auth=params.get("trustForClientAuth"),
            trust_for_ise_auth=params.get("trustForIseAuth"),
            id=params.get("id"),
        )

    def get_object_by_name(self, name):
        # NOTICE: Get does not support/work for filter by name with EQ
        result = None
        gen_items_responses = self.ise.exec(
            family="certificates",
            function="get_trusted_certificates_generator"
        )
        try:
            for items_response in gen_items_responses:
                items = items_response.response.get('response', [])
                result = get_dict_result(items, 'name', name)
                if result:
                    return result
        except (TypeError, AttributeError) as e:
            self.ise.fail_json(
                msg=(
                    "An error occured when executing operation."
                    " Check the configuration of your API Settings and API Gateway settings on your ISE server."
                    " This collection assumes that the API Gateway, the ERS APIs and OpenAPIs are enabled."
                    " You may want to enable the (ise_debug: True) argument."
                    " The error was: {error}"
                ).format(error=e)
            )
        except Exception:
            result = None
            return result
        return result

    def get_object_by_id(self, id):
        try:
            result = self.ise.exec(
                family="certificates",
                function="get_trusted_certificate_by_id",
                params={"id": id},
                handle_func_exception=False,
            ).response['response']
        except (TypeError, AttributeError) as e:
            self.ise.fail_json(
                msg=(
                    "An error occured when executing operation."
                    " Check the configuration of your API Settings and API Gateway settings on your ISE server."
                    " This collection assumes that the API Gateway, the ERS APIs and OpenAPIs are enabled."
                    " You may want to enable the (ise_debug: True) argument."
                    " The error was: {error}"
                ).format(error=e)
            )
        except Exception:
            result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get("id")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters("The 'id' and 'name' params don't refer to the same object")
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("authenticateBeforeCRLReceived", "authenticate_before_crl_received"),
            ("automaticCRLUpdate", "automatic_crl_update"),
            ("automaticCRLUpdatePeriod", "automatic_crl_update_period"),
            ("automaticCRLUpdateUnits", "automatic_crl_update_units"),
            ("crlDistributionUrl", "crl_distribution_url"),
            ("crlDownloadFailureRetries", "crl_download_failure_retries"),
            ("crlDownloadFailureRetriesUnits", "crl_download_failure_retries_units"),
            ("description", "description"),
            ("downloadCRL", "download_crl"),
            ("enableOCSPValidation", "enable_ocsp_validation"),
            ("enableServerIdentityCheck", "enable_server_identity_check"),
            ("ignoreCRLExpiration", "ignore_crl_expiration"),
            ("name", "name"),
            ("nonAutomaticCRLUpdatePeriod", "non_automatic_crl_update_period"),
            ("nonAutomaticCRLUpdateUnits", "non_automatic_crl_update_units"),
            ("rejectIfNoStatusFromOCSP", "reject_if_no_status_from_ocs_p"),
            ("rejectIfUnreachableFromOCSP", "reject_if_unreachable_from_ocs_p"),
            ("selectedOCSPService", "selected_ocsp_service"),
            ("status", "status"),
            ("trustForCertificateBasedAdminAuth", "trust_for_certificate_based_admin_auth"),
            ("trustForCiscoServicesAuth", "trust_for_cisco_services_auth"),
            ("trustForClientAuth", "trust_for_client_auth"),
            ("trustForIseAuth", "trust_for_ise_auth"),
            ("id", "id"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not ise_compare_equality(current_obj.get(ise_param),
                                            requested_obj.get(ansible_param))
                   for (ise_param, ansible_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            id_ = self.get_object_by_name(name).get("id")
            self.new_object.update(dict(id=id_))
        result = self.ise.exec(
            family="certificates",
            function="update_trusted_certificate",
            params=self.new_object
        ).response
        return result

    def delete(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        if not id:
            id_ = self.get_object_by_name(name).get("id")
            self.new_object.update(dict(id=id_))
        result = self.ise.exec(
            family="certificates",
            function="delete_trusted_certificate_by_id",
            params=self.new_object
        ).response
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail("ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        ise = ISESDK(params=self._task.args)
        obj = TrustedCertificate(self._task.args, ise)

        state = self._task.args.get("state")

        response = None
        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    ise_update_response = obj.update()
                    self._result.update(dict(ise_update_response=ise_update_response))
                    (obj_exists, updated_obj) = obj.exists()
                    response = updated_obj
                    ise.object_updated()
                else:
                    response = prev_obj
                    ise.object_already_present()
            else:
                ise.fail_json("Object does not exists, plugin only has update")
        elif state == "absent":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                obj.delete()
                response = prev_obj
                ise.object_deleted()
            else:
                ise.object_already_absent()

        self._result.update(dict(ise_response=response))
        self._result.update(ise.exit_json())
        return self._result
