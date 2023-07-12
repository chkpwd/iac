# -*- coding: utf-8 -*-

# (c) 2023, Daniel Turecek (dturecek@purestorage.com)
# GNU General Public License v3.0+ (see COPYING.GPLv3 or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

try:
    import fusion as purefusion
except ImportError:
    pass


def get_array(module, fusion, array_name=None):
    """Return Array or None"""
    array_api_instance = purefusion.ArraysApi(fusion)
    try:
        if array_name is None:
            array_name = module.params["array"]

        return array_api_instance.get_array(
            array_name=array_name,
            availability_zone_name=module.params["availability_zone"],
            region_name=module.params["region"],
        )
    except purefusion.rest.ApiException:
        return None


def get_az(module, fusion, availability_zone_name=None):
    """Get Availability Zone or None"""
    az_api_instance = purefusion.AvailabilityZonesApi(fusion)
    try:
        if availability_zone_name is None:
            availability_zone_name = module.params["availability_zone"]

        return az_api_instance.get_availability_zone(
            region_name=module.params["region"],
            availability_zone_name=availability_zone_name,
        )
    except purefusion.rest.ApiException:
        return None


def get_region(module, fusion, region_name=None):
    """Get Region or None"""
    region_api_instance = purefusion.RegionsApi(fusion)
    try:
        if region_name is None:
            region_name = module.params["region"]

        return region_api_instance.get_region(
            region_name=region_name,
        )
    except purefusion.rest.ApiException:
        return None


def get_ss(module, fusion, storage_service_name=None):
    """Return Storage Service or None"""
    ss_api_instance = purefusion.StorageServicesApi(fusion)
    try:
        if storage_service_name is None:
            storage_service_name = module.params["storage_service"]

        return ss_api_instance.get_storage_service(
            storage_service_name=storage_service_name
        )
    except purefusion.rest.ApiException:
        return None


def get_tenant(module, fusion, tenant_name=None):
    """Return Tenant or None"""
    api_instance = purefusion.TenantsApi(fusion)
    try:
        if tenant_name is None:
            tenant_name = module.params["tenant"]

        return api_instance.get_tenant(tenant_name=tenant_name)
    except purefusion.rest.ApiException:
        return None


def get_ts(module, fusion, tenant_space_name=None):
    """Tenant Space or None"""
    ts_api_instance = purefusion.TenantSpacesApi(fusion)
    try:
        if tenant_space_name is None:
            tenant_space_name = module.params["tenant_space"]

        return ts_api_instance.get_tenant_space(
            tenant_name=module.params["tenant"],
            tenant_space_name=tenant_space_name,
        )
    except purefusion.rest.ApiException:
        return None
