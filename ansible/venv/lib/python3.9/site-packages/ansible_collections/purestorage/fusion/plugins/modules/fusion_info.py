#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2021, Simon Dodsley (simon@purestorage.com), Andrej Pajtas (apajtas@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = r"""
---
module: fusion_info
version_added: '1.0.0'
short_description: Collect information from Pure Fusion
description:
  - Collect information from a Pure Fusion environment.
  - By default, the module will collect basic
    information including counts for arrays, availability_zones, volumes, snapshots
    . Fleet capacity and data reduction rates are also provided.
  - Additional information can be collected based on the configured set of arguments.
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
notes:
- Supports C(check mode).
options:
  gather_subset:
    description:
      - When supplied, this argument will define the information to be collected.
        Possible values for this include all, minimum, roles, users, arrays, hardware_types,
        volumes, host_access_policies, storage_classes, protection_policies, placement_groups,
        network_interfaces, availability_zones, network_interface_groups, storage_endpoints,
        snapshots, regions, storage_services, tenants, tenant_spaces, network_interface_groups and api_clients.
    type: list
    elements: str
    required: false
    default: minimum
extends_documentation_fragment:
  - purestorage.fusion.purestorage.fusion
"""

EXAMPLES = r"""
- name: Collect default set of information
  purestorage.fusion.fusion_info:
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"
    register: fusion_info

- name: Show default information
  ansible.builtin.debug:
    msg: "{{ fusion_info['fusion_info']['default'] }}"

- name: Collect all information
  purestorage.fusion.fusion_info:
    gather_subset:
      - all
    issuer_id: key_name
    private_key_file: "az-admin-private-key.pem"

- name: Show all information
  ansible.builtin.debug:
    msg: "{{ fusion_info['fusion_info'] }}"
"""

RETURN = r"""
fusion_info:
  description: Returns the information collected from Fusion
  returned: always
  type: dict
"""

try:
    import fusion as purefusion
except ImportError:
    pass

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.fusion.plugins.module_utils.fusion import (
    fusion_argument_spec,
)
from ansible_collections.purestorage.fusion.plugins.module_utils.startup import (
    setup_fusion,
)
import time
import http


def _convert_microseconds(micros):
    seconds = (micros / 1000) % 60
    minutes = (micros / (1000 * 60)) % 60
    hours = (micros / (1000 * 60 * 60)) % 24
    return seconds, minutes, hours


def _api_permission_denied_handler(name):
    """Return decorator which catches #403 errors"""

    def inner(func):
        def wrapper(module, fusion, *args, **kwargs):
            try:
                return func(module, fusion, *args, **kwargs)
            except purefusion.rest.ApiException as exc:
                if exc.status == http.HTTPStatus.FORBIDDEN:
                    module.warn(f"Cannot get [{name} dict], reason: Permission denied")
                    return None
                else:
                    # other exceptions will be handled by our exception hook
                    raise exc

        return wrapper

    return inner


def generate_default_dict(module, fusion):
    def warning_api_exception(name):
        module.warn(f"Cannot get {name} in [default dict], reason: Permission denied")

    def warning_argument_none(name, requirement):
        module.warn(
            f"Cannot get {name} in [default dict], reason: Required argument `{requirement}` not available."
        )

    # All values are independent on each other - if getting one value fails, we will show warning and continue.
    # That's also the reason why there's so many nested for loops repeating all over again.
    version = None
    users_num = None
    protection_policies_num = None
    host_access_policies_num = None
    hardware_types_num = None
    storage_services = None
    storage_services_num = None
    tenants = None
    tenants_num = None
    regions = None
    regions_num = None
    roles = None
    roles_num = None
    storage_classes_num = None
    role_assignments_num = None
    tenant_spaces_num = None
    volumes_num = None
    placement_groups_num = None
    snapshots_num = None
    availability_zones_num = None
    arrays_num = None
    network_interfaces_num = None
    network_interface_groups_num = None
    storage_endpoints_num = None

    try:
        version = purefusion.DefaultApi(fusion).get_version().version
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("API version")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        users_num = len(purefusion.IdentityManagerApi(fusion).list_users())
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Users")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        protection_policies_num = len(
            purefusion.ProtectionPoliciesApi(fusion).list_protection_policies().items
        )
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Protection Policies")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        host_access_policies_num = len(
            purefusion.HostAccessPoliciesApi(fusion).list_host_access_policies().items
        )
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Host Access Policies")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        hardware_types_num = len(
            purefusion.HardwareTypesApi(fusion).list_hardware_types().items
        )
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Hardware Types")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        storage_services = purefusion.StorageServicesApi(fusion).list_storage_services()
        storage_services_num = len(storage_services.items)
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Storage Services")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        tenants = purefusion.TenantsApi(fusion).list_tenants()
        tenants_num = len(tenants.items)
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Tenants")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        regions = purefusion.RegionsApi(fusion).list_regions()
        regions_num = len(regions.items)
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Regions")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    try:
        roles = purefusion.RolesApi(fusion).list_roles()
        roles_num = len(roles)
    except purefusion.rest.ApiException as exc:
        if exc.status == http.HTTPStatus.FORBIDDEN:
            warning_api_exception("Roles")
        else:
            # other exceptions will be handled by our exception hook
            raise exc

    if storage_services is not None:
        try:
            storage_class_api_instance = purefusion.StorageClassesApi(fusion)
            storage_classes_num = sum(
                len(
                    storage_class_api_instance.list_storage_classes(
                        storage_service_name=storage_service.name
                    ).items
                )
                for storage_service in storage_services.items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Storage Classes")
            else:
                # other exceptions will be handled by our exception hook
                raise exc
    else:
        warning_argument_none("Storage Classes", "storage_services")

    if roles is not None:
        try:
            role_assign_api_instance = purefusion.RoleAssignmentsApi(fusion)
            role_assignments_num = sum(
                len(role_assign_api_instance.list_role_assignments(role_name=role.name))
                for role in roles
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Role Assignments")
            else:
                # other exceptions will be handled by our exception hook
                raise exc
    else:
        warning_argument_none("Role Assignments", "roles")

    if tenants is not None:
        tenantspace_api_instance = purefusion.TenantSpacesApi(fusion)

        try:
            tenant_spaces_num = sum(
                len(
                    tenantspace_api_instance.list_tenant_spaces(
                        tenant_name=tenant.name
                    ).items
                )
                for tenant in tenants.items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Tenant Spaces")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            vol_api_instance = purefusion.VolumesApi(fusion)
            volumes_num = sum(
                len(
                    vol_api_instance.list_volumes(
                        tenant_name=tenant.name,
                        tenant_space_name=tenant_space.name,
                    ).items
                )
                for tenant in tenants.items
                for tenant_space in tenantspace_api_instance.list_tenant_spaces(
                    tenant_name=tenant.name
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Volumes")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            plgrp_api_instance = purefusion.PlacementGroupsApi(fusion)
            placement_groups_num = sum(
                len(
                    plgrp_api_instance.list_placement_groups(
                        tenant_name=tenant.name,
                        tenant_space_name=tenant_space.name,
                    ).items
                )
                for tenant in tenants.items
                for tenant_space in tenantspace_api_instance.list_tenant_spaces(
                    tenant_name=tenant.name
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Placement Groups")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            snapshot_api_instance = purefusion.SnapshotsApi(fusion)
            snapshots_num = sum(
                len(
                    snapshot_api_instance.list_snapshots(
                        tenant_name=tenant.name,
                        tenant_space_name=tenant_space.name,
                    ).items
                )
                for tenant in tenants.items
                for tenant_space in tenantspace_api_instance.list_tenant_spaces(
                    tenant_name=tenant.name
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Snapshots")
            else:
                # other exceptions will be handled by our exception hook
                raise exc
    else:
        warning_argument_none("Tenant Spaces", "tenants")
        warning_argument_none("Volumes", "tenants")
        warning_argument_none("Placement Groups", "tenants")
        warning_argument_none("Snapshots", "tenants")

    if regions is not None:
        az_api_instance = purefusion.AvailabilityZonesApi(fusion)

        try:
            availability_zones_num = sum(
                len(
                    az_api_instance.list_availability_zones(
                        region_name=region.name
                    ).items
                )
                for region in regions.items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Availability Zones")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            arrays_api_instance = purefusion.ArraysApi(fusion)
            arrays_num = sum(
                len(
                    arrays_api_instance.list_arrays(
                        availability_zone_name=availability_zone.name,
                        region_name=region.name,
                    ).items
                )
                for region in regions.items
                for availability_zone in az_api_instance.list_availability_zones(
                    region_name=region.name
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Arrays")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
            network_interface_groups_num = sum(
                len(
                    nig_api_instance.list_network_interface_groups(
                        availability_zone_name=availability_zone.name,
                        region_name=region.name,
                    ).items
                )
                for region in regions.items
                for availability_zone in az_api_instance.list_availability_zones(
                    region_name=region.name
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Network Interface Groups")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            send_api_instance = purefusion.StorageEndpointsApi(fusion)
            storage_endpoints_num = sum(
                len(
                    send_api_instance.list_storage_endpoints(
                        availability_zone_name=availability_zone.name,
                        region_name=region.name,
                    ).items
                )
                for region in regions.items
                for availability_zone in az_api_instance.list_availability_zones(
                    region_name=region.name
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Storage Endpoints")
            else:
                # other exceptions will be handled by our exception hook
                raise exc

        try:
            nic_api_instance = purefusion.NetworkInterfacesApi(fusion)
            network_interfaces_num = sum(
                len(
                    nic_api_instance.list_network_interfaces(
                        availability_zone_name=availability_zone.name,
                        region_name=region.name,
                        array_name=array_detail.name,
                    ).items
                )
                for region in regions.items
                for availability_zone in az_api_instance.list_availability_zones(
                    region_name=region.name
                ).items
                for array_detail in arrays_api_instance.list_arrays(
                    availability_zone_name=availability_zone.name,
                    region_name=region.name,
                ).items
            )
        except purefusion.rest.ApiException as exc:
            if exc.status == http.HTTPStatus.FORBIDDEN:
                warning_api_exception("Network Interfaces")
            else:
                # other exceptions will be handled by our exception hook
                raise exc
    else:
        warning_argument_none("Availability Zones", "regions")
        warning_argument_none("Network Interfaces", "regions")
        warning_argument_none("Network Interface Groups", "regions")
        warning_argument_none("Storage Endpoints", "regions")
        warning_argument_none("Arrays", "regions")

    return {
        "version": version,
        "users": users_num,
        "protection_policies": protection_policies_num,
        "host_access_policies": host_access_policies_num,
        "hardware_types": hardware_types_num,
        "storage_services": storage_services_num,
        "tenants": tenants_num,
        "regions": regions_num,
        "storage_classes": storage_classes_num,
        "roles": roles_num,
        "role_assignments": role_assignments_num,
        "tenant_spaces": tenant_spaces_num,
        "volumes": volumes_num,
        "placement_groups": placement_groups_num,
        "snapshots": snapshots_num,
        "availability_zones": availability_zones_num,
        "arrays": arrays_num,
        "network_interfaces": network_interfaces_num,
        "network_interface_groups": network_interface_groups_num,
        "storage_endpoints": storage_endpoints_num,
    }


@_api_permission_denied_handler("network_interfaces")
def generate_nics_dict(module, fusion):
    nics_info = {}
    nic_api_instance = purefusion.NetworkInterfacesApi(fusion)
    arrays_api_instance = purefusion.ArraysApi(fusion)
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    regions_api_instance = purefusion.RegionsApi(fusion)
    regions = regions_api_instance.list_regions()
    for region in regions.items:
        azs = az_api_instance.list_availability_zones(region_name=region.name)
        for az in azs.items:
            array_details = arrays_api_instance.list_arrays(
                availability_zone_name=az.name,
                region_name=region.name,
            )
            for array_detail in array_details.items:
                array_name = az.name + "/" + array_detail.name
                nics_info[array_name] = {}
                nics = nic_api_instance.list_network_interfaces(
                    availability_zone_name=az.name,
                    region_name=region.name,
                    array_name=array_detail.name,
                )

                for nic in nics.items:
                    nics_info[array_name][nic.name] = {
                        "enabled": nic.enabled,
                        "display_name": nic.display_name,
                        "interface_type": nic.interface_type,
                        "services": nic.services,
                        "max_speed": nic.max_speed,
                        "vlan": nic.eth.vlan,
                        "address": nic.eth.address,
                        "mac_address": nic.eth.mac_address,
                        "gateway": nic.eth.gateway,
                        "mtu": nic.eth.mtu,
                        "network_interface_group": nic.network_interface_group.name,
                        "availability_zone": nic.availability_zone.name,
                    }
    return nics_info


@_api_permission_denied_handler("host_access_policies")
def generate_hap_dict(module, fusion):
    hap_info = {}
    api_instance = purefusion.HostAccessPoliciesApi(fusion)
    hosts = api_instance.list_host_access_policies()
    for host in hosts.items:
        name = host.name
        hap_info[name] = {
            "personality": host.personality,
            "display_name": host.display_name,
            "iqn": host.iqn,
        }
    return hap_info


@_api_permission_denied_handler("arrays")
def generate_array_dict(module, fusion):
    array_info = {}
    array_api_instance = purefusion.ArraysApi(fusion)
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    regions_api_instance = purefusion.RegionsApi(fusion)
    regions = regions_api_instance.list_regions()
    for region in regions.items:
        azs = az_api_instance.list_availability_zones(region_name=region.name)
        for az in azs.items:
            arrays = array_api_instance.list_arrays(
                availability_zone_name=az.name,
                region_name=region.name,
            )
            for array in arrays.items:
                array_name = array.name
                array_space = array_api_instance.get_array_space(
                    availability_zone_name=az.name,
                    array_name=array_name,
                    region_name=region.name,
                )
                array_perf = array_api_instance.get_array_performance(
                    availability_zone_name=az.name,
                    array_name=array_name,
                    region_name=region.name,
                )
                array_info[array_name] = {
                    "region": region.name,
                    "availability_zone": az.name,
                    "host_name": array.host_name,
                    "maintenance_mode": array.maintenance_mode,
                    "unavailable_mode": array.unavailable_mode,
                    "display_name": array.display_name,
                    "hardware_type": array.hardware_type.name,
                    "appliance_id": array.appliance_id,
                    "apartment_id": getattr(array, "apartment_id", None),
                    "space": {
                        "total_physical_space": array_space.total_physical_space,
                    },
                    "performance": {
                        "read_bandwidth": array_perf.read_bandwidth,
                        "read_latency_us": array_perf.read_latency_us,
                        "reads_per_sec": array_perf.reads_per_sec,
                        "write_bandwidth": array_perf.write_bandwidth,
                        "write_latency_us": array_perf.write_latency_us,
                        "writes_per_sec": array_perf.writes_per_sec,
                    },
                }
    return array_info


@_api_permission_denied_handler("placement_groups")
def generate_pg_dict(module, fusion):
    pg_info = {}
    tenant_api_instance = purefusion.TenantsApi(fusion)
    tenantspace_api_instance = purefusion.TenantSpacesApi(fusion)
    pg_api_instance = purefusion.PlacementGroupsApi(fusion)
    tenants = tenant_api_instance.list_tenants()
    for tenant in tenants.items:
        tenant_spaces = tenantspace_api_instance.list_tenant_spaces(
            tenant_name=tenant.name
        ).items
        for tenant_space in tenant_spaces:
            groups = pg_api_instance.list_placement_groups(
                tenant_name=tenant.name,
                tenant_space_name=tenant_space.name,
            )
            for group in groups.items:
                group_name = tenant.name + "/" + tenant_space.name + "/" + group.name
                pg_info[group_name] = {
                    "tenant": group.tenant.name,
                    "display_name": group.display_name,
                    "placement_engine": group.placement_engine,
                    "tenant_space": group.tenant_space.name,
                    "az": group.availability_zone.name,
                    "array": getattr(group.array, "name", None),
                }
    return pg_info


@_api_permission_denied_handler("tenant_spaces")
def generate_ts_dict(module, fusion):
    ts_info = {}
    tenant_api_instance = purefusion.TenantsApi(fusion)
    tenantspace_api_instance = purefusion.TenantSpacesApi(fusion)
    tenants = tenant_api_instance.list_tenants()
    for tenant in tenants.items:
        tenant_spaces = tenantspace_api_instance.list_tenant_spaces(
            tenant_name=tenant.name
        ).items
        for tenant_space in tenant_spaces:
            ts_name = tenant.name + "/" + tenant_space.name
            ts_info[ts_name] = {
                "tenant": tenant.name,
                "display_name": tenant_space.display_name,
            }
    return ts_info


@_api_permission_denied_handler("protection_policies")
def generate_pp_dict(module, fusion):
    pp_info = {}
    api_instance = purefusion.ProtectionPoliciesApi(fusion)
    policies = api_instance.list_protection_policies()
    for policy in policies.items:
        policy_name = policy.name
        pp_info[policy_name] = {
            "objectives": policy.objectives,
        }
    return pp_info


@_api_permission_denied_handler("tenants")
def generate_tenant_dict(module, fusion):
    tenants_api_instance = purefusion.TenantsApi(fusion)
    return {
        tenant.name: {
            "display_name": tenant.display_name,
        }
        for tenant in tenants_api_instance.list_tenants().items
    }


@_api_permission_denied_handler("regions")
def generate_regions_dict(module, fusion):
    regions_api_instance = purefusion.RegionsApi(fusion)
    return {
        region.name: {
            "display_name": region.display_name,
        }
        for region in regions_api_instance.list_regions().items
    }


@_api_permission_denied_handler("availability_zones")
def generate_zones_dict(module, fusion):
    zones_info = {}
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    regions_api_instance = purefusion.RegionsApi(fusion)
    regions = regions_api_instance.list_regions()
    for region in regions.items:
        zones = az_api_instance.list_availability_zones(region_name=region.name)
        for zone in zones.items:
            az_name = zone.name
            zones_info[az_name] = {
                "display_name": zone.display_name,
                "region": zone.region.name,
            }
    return zones_info


@_api_permission_denied_handler("role_assignments")
def generate_ras_dict(module, fusion):
    ras_info = {}
    ras_api_instance = purefusion.RoleAssignmentsApi(fusion)
    role_api_instance = purefusion.RolesApi(fusion)
    roles = role_api_instance.list_roles()
    for role in roles:
        ras = ras_api_instance.list_role_assignments(role_name=role.name)
        for assignment in ras:
            name = assignment.name
            ras_info[name] = {
                "display_name": assignment.display_name,
                "role": assignment.role.name,
                "scope": assignment.scope.name,
            }
    return ras_info


@_api_permission_denied_handler("roles")
def generate_roles_dict(module, fusion):
    roles_info = {}
    api_instance = purefusion.RolesApi(fusion)
    roles = api_instance.list_roles()
    for role in roles:
        name = role.name
        roles_info[name] = {
            "display_name": role.display_name,
            "scopes": role.assignable_scopes,
        }
    return roles_info


@_api_permission_denied_handler("api_clients")
def generate_api_client_dict(module, fusion):
    client_info = {}
    api_instance = purefusion.IdentityManagerApi(fusion)
    clients = api_instance.list_api_clients()
    for client in clients:
        client_info[client.name] = {
            "display_name": client.display_name,
            "issuer": client.issuer,
            "public_key": client.public_key,
            "creator_id": client.creator_id,
            "last_key_update": time.strftime(
                "%a, %d %b %Y %H:%M:%S %Z",
                time.localtime(client.last_key_update / 1000),
            ),
            "last_used": time.strftime(
                "%a, %d %b %Y %H:%M:%S %Z",
                time.localtime(client.last_used / 1000),
            ),
        }
    return client_info


@_api_permission_denied_handler("users")
def generate_users_dict(module, fusion):
    users_info = {}
    api_instance = purefusion.IdentityManagerApi(fusion)
    users = api_instance.list_users()
    for user in users:
        users_info[user.name] = {
            "display_name": user.display_name,
            "email": user.email,
            "id": user.id,
        }
    return users_info


@_api_permission_denied_handler("hardware_types")
def generate_hardware_types_dict(module, fusion):
    hardware_info = {}
    api_instance = purefusion.HardwareTypesApi(fusion)
    hw_types = api_instance.list_hardware_types()
    for hw_type in hw_types.items:
        hardware_info[hw_type.name] = {
            "array_type": hw_type.array_type,
            "display_name": hw_type.display_name,
            "media_type": hw_type.media_type,
        }
    return hardware_info


@_api_permission_denied_handler("storage_classes")
def generate_sc_dict(module, fusion):
    sc_info = {}
    ss_api_instance = purefusion.StorageServicesApi(fusion)
    sc_api_instance = purefusion.StorageClassesApi(fusion)
    services = ss_api_instance.list_storage_services()
    for service in services.items:
        classes = sc_api_instance.list_storage_classes(
            storage_service_name=service.name,
        )
        for s_class in classes.items:
            sc_info[s_class.name] = {
                "bandwidth_limit": getattr(s_class, "bandwidth_limit", None),
                "iops_limit": getattr(s_class, "iops_limit", None),
                "size_limit": getattr(s_class, "size_limit", None),
                "display_name": s_class.display_name,
                "storage_service": service.name,
            }
    return sc_info


@_api_permission_denied_handler("storage_services")
def generate_storserv_dict(module, fusion):
    ss_dict = {}
    ss_api_instance = purefusion.StorageServicesApi(fusion)
    services = ss_api_instance.list_storage_services()
    for service in services.items:
        ss_dict[service.name] = {
            "display_name": service.display_name,
            "hardware_types": None,
        }
        # can be None if we don't have permission to see this
        if service.hardware_types is not None:
            ss_dict[service.name]["hardware_types"] = []
            for hwtype in service.hardware_types:
                ss_dict[service.name]["hardware_types"].append(hwtype.name)
    return ss_dict


@_api_permission_denied_handler("storage_endpoints")
def generate_se_dict(module, fusion):
    se_dict = {}
    se_api_instance = purefusion.StorageEndpointsApi(fusion)
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    regions_api_instance = purefusion.RegionsApi(fusion)
    regions = regions_api_instance.list_regions()
    for region in regions.items:
        azs = az_api_instance.list_availability_zones(region_name=region.name)
        for az in azs.items:
            endpoints = se_api_instance.list_storage_endpoints(
                region_name=region.name,
                availability_zone_name=az.name,
            )
            for endpoint in endpoints.items:
                name = region.name + "/" + az.name + "/" + endpoint.name
                se_dict[name] = {
                    "display_name": endpoint.display_name,
                    "endpoint_type": endpoint.endpoint_type,
                    "iscsi_interfaces": [],
                }
                for iface in endpoint.iscsi.discovery_interfaces:
                    dct = {
                        "address": iface.address,
                        "gateway": iface.gateway,
                        "mtu": iface.mtu,
                        "network_interface_groups": None,
                    }
                    if iface.network_interface_groups is not None:
                        dct["network_interface_groups"] = [
                            nig.name for nig in iface.network_interface_groups
                        ]
                    se_dict[name]["iscsi_interfaces"].append(dct)
    return se_dict


@_api_permission_denied_handler("network_interface_groups")
def generate_nigs_dict(module, fusion):
    nigs_dict = {}
    nig_api_instance = purefusion.NetworkInterfaceGroupsApi(fusion)
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    regions_api_instance = purefusion.RegionsApi(fusion)
    regions = regions_api_instance.list_regions()
    for region in regions.items:
        azs = az_api_instance.list_availability_zones(region_name=region.name)
        for az in azs.items:
            nigs = nig_api_instance.list_network_interface_groups(
                region_name=region.name,
                availability_zone_name=az.name,
            )
            for nig in nigs.items:
                name = region.name + "/" + az.name + "/" + nig.name
                nigs_dict[name] = {
                    "display_name": nig.display_name,
                    "gateway": nig.eth.gateway,
                    "prefix": nig.eth.prefix,
                    "mtu": nig.eth.mtu,
                }
    return nigs_dict


@_api_permission_denied_handler("snapshots")
def generate_snap_dicts(module, fusion):
    snap_dict = {}
    vsnap_dict = {}
    tenant_api_instance = purefusion.TenantsApi(fusion)
    tenantspace_api_instance = purefusion.TenantSpacesApi(fusion)
    snap_api_instance = purefusion.SnapshotsApi(fusion)
    vsnap_api_instance = purefusion.VolumeSnapshotsApi(fusion)
    tenants = tenant_api_instance.list_tenants()
    for tenant in tenants.items:
        tenant_spaces = tenantspace_api_instance.list_tenant_spaces(
            tenant_name=tenant.name
        ).items
        for tenant_space in tenant_spaces:
            snaps = snap_api_instance.list_snapshots(
                tenant_name=tenant.name,
                tenant_space_name=tenant_space.name,
            )
            for snap in snaps.items:
                snap_name = tenant.name + "/" + tenant_space.name + "/" + snap.name
                secs, mins, hours = _convert_microseconds(snap.time_remaining)
                snap_dict[snap_name] = {
                    "display_name": snap.display_name,
                    "protection_policy": snap.protection_policy,
                    "time_remaining": "{0} hours, {1} mins, {2} secs".format(
                        int(hours), int(mins), int(secs)
                    ),
                    "volume_snapshots_link": snap.volume_snapshots_link,
                }
                vsnaps = vsnap_api_instance.list_volume_snapshots(
                    tenant_name=tenant.name,
                    tenant_space_name=tenant_space.name,
                    snapshot_name=snap.name,
                )
                for vsnap in vsnaps.items:
                    vsnap_name = (
                        tenant.name
                        + "/"
                        + tenant_space.name
                        + "/"
                        + snap.name
                        + "/"
                        + vsnap.name
                    )
                    secs, mins, hours = _convert_microseconds(vsnap.time_remaining)
                    vsnap_dict[vsnap_name] = {
                        "size": vsnap.size,
                        "display_name": vsnap.display_name,
                        "protection_policy": vsnap.protection_policy,
                        "serial_number": vsnap.serial_number,
                        "created_at": time.strftime(
                            "%a, %d %b %Y %H:%M:%S %Z",
                            time.localtime(vsnap.created_at / 1000),
                        ),
                        "time_remaining": "{0} hours, {1} mins, {2} secs".format(
                            int(hours), int(mins), int(secs)
                        ),
                        "placement_group": vsnap.placement_group.name,
                    }
    return snap_dict, vsnap_dict


@_api_permission_denied_handler("volumes")
def generate_volumes_dict(module, fusion):
    volume_info = {}

    tenant_api_instance = purefusion.TenantsApi(fusion)
    vol_api_instance = purefusion.VolumesApi(fusion)
    tenant_space_api_instance = purefusion.TenantSpacesApi(fusion)

    tenants = tenant_api_instance.list_tenants()
    for tenant in tenants.items:
        tenant_spaces = tenant_space_api_instance.list_tenant_spaces(
            tenant_name=tenant.name
        ).items
        for tenant_space in tenant_spaces:
            volumes = vol_api_instance.list_volumes(
                tenant_name=tenant.name,
                tenant_space_name=tenant_space.name,
            )
            for volume in volumes.items:
                vol_name = tenant.name + "/" + tenant_space.name + "/" + volume.name
                volume_info[vol_name] = {
                    "tenant": tenant.name,
                    "tenant_space": tenant_space.name,
                    "name": volume.name,
                    "size": volume.size,
                    "display_name": volume.display_name,
                    "placement_group": volume.placement_group.name,
                    "source_volume_snapshot": getattr(
                        volume.source_volume_snapshot, "name", None
                    ),
                    "protection_policy": getattr(
                        volume.protection_policy, "name", None
                    ),
                    "storage_class": volume.storage_class.name,
                    "serial_number": volume.serial_number,
                    "target": {},
                    "array": getattr(volume.array, "name", None),
                }

                volume_info[vol_name]["target"] = {
                    "iscsi": {
                        "addresses": volume.target.iscsi.addresses,
                        "iqn": volume.target.iscsi.iqn,
                    },
                    "nvme": {
                        "addresses": None,
                        "nqn": None,
                    },
                    "fc": {
                        "addresses": None,
                        "wwns": None,
                    },
                }
    return volume_info


def main():
    argument_spec = fusion_argument_spec()
    argument_spec.update(
        dict(gather_subset=dict(default="minimum", type="list", elements="str"))
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    # will handle all errors (except #403 which should be handled in code)
    fusion = setup_fusion(module)

    subset = [test.lower() for test in module.params["gather_subset"]]
    valid_subsets = (
        "all",
        "minimum",
        "roles",
        "users",
        "placements",
        "arrays",
        "hardware_types",
        "volumes",
        "hosts",
        "storage_classes",
        "protection_policies",
        "placement_groups",
        "interfaces",
        "zones",
        "nigs",
        "storage_endpoints",
        "snapshots",
        "storage_services",
        "tenants",
        "tenant_spaces",
        "network_interface_groups",
        "api_clients",
        "availability_zones",
        "host_access_policies",
        "network_interfaces",
        "regions",
    )
    for option in subset:
        if option not in valid_subsets:
            module.fail_json(
                msg=f"value gather_subset must be one or more of: {','.join(valid_subsets)}, got: {','.join(subset)}\nvalue {option} is not allowed"
            )

    info = {}

    if "minimum" in subset or "all" in subset:
        info["default"] = generate_default_dict(module, fusion)
    if "hardware_types" in subset or "all" in subset:
        info["hardware_types"] = generate_hardware_types_dict(module, fusion)
    if "users" in subset or "all" in subset:
        info["users"] = generate_users_dict(module, fusion)
    if "regions" in subset or "all" in subset:
        info["regions"] = generate_regions_dict(module, fusion)
    if "availability_zones" in subset or "all" in subset or "zones" in subset:
        info["availability_zones"] = generate_zones_dict(module, fusion)
        if "zones" in subset:
            module.warn(
                "The 'zones' subset is deprecated and will be removed in the version 2.0.0\nUse 'availability_zones' subset instead."
            )
    if "roles" in subset or "all" in subset:
        info["roles"] = generate_roles_dict(module, fusion)
        info["role_assignments"] = generate_ras_dict(module, fusion)
    if "storage_services" in subset or "all" in subset:
        info["storage_services"] = generate_storserv_dict(module, fusion)
    if "volumes" in subset or "all" in subset:
        info["volumes"] = generate_volumes_dict(module, fusion)
    if "protection_policies" in subset or "all" in subset:
        info["protection_policies"] = generate_pp_dict(module, fusion)
    if "placement_groups" in subset or "all" in subset or "placements" in subset:
        info["placement_groups"] = generate_pg_dict(module, fusion)
        if "placements" in subset:
            module.warn(
                "The 'placements' subset is deprecated and will be removed in the version 1.7.0"
            )
    if "storage_classes" in subset or "all" in subset:
        info["storage_classes"] = generate_sc_dict(module, fusion)
    if "network_interfaces" in subset or "all" in subset or "interfaces" in subset:
        info["network_interfaces"] = generate_nics_dict(module, fusion)
        if "interfaces" in subset:
            module.warn(
                "The 'interfaces' subset is deprecated and will be removed in the version 2.0.0\nUse 'network_interfaces' subset instead."
            )
    if "host_access_policies" in subset or "all" in subset or "hosts" in subset:
        info["host_access_policies"] = generate_hap_dict(module, fusion)
        if "hosts" in subset:
            module.warn(
                "The 'hosts' subset is deprecated and will be removed in the version 2.0.0\nUse 'host_access_policies' subset instead."
            )
    if "arrays" in subset or "all" in subset:
        info["arrays"] = generate_array_dict(module, fusion)
    if "tenants" in subset or "all" in subset:
        info["tenants"] = generate_tenant_dict(module, fusion)
    if "tenant_spaces" in subset or "all" in subset:
        info["tenant_spaces"] = generate_ts_dict(module, fusion)
    if "storage_endpoints" in subset or "all" in subset:
        info["storage_endpoints"] = generate_se_dict(module, fusion)
    if "api_clients" in subset or "all" in subset:
        info["api_clients"] = generate_api_client_dict(module, fusion)
    if "network_interface_groups" in subset or "all" in subset or "nigs" in subset:
        info["network_interface_groups"] = generate_nigs_dict(module, fusion)
        if "nigs" in subset:
            module.warn(
                "The 'nigs' subset is deprecated and will be removed in the version 1.7.0"
            )
    if "snapshots" in subset or "all" in subset:
        snap_dicts = generate_snap_dicts(module, fusion)
        if snap_dicts is not None:
            info["snapshots"], info["volume_snapshots"] = snap_dicts
        else:
            info["snapshots"], info["volume_snapshots"] = None, None

    module.exit_json(changed=False, fusion_info=info)


if __name__ == "__main__":
    main()
