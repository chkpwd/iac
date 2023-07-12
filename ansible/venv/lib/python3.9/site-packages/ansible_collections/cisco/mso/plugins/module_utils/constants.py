FILTER_KEY_MAP = {
    "both-way": "filterRelationships",
    "consumer-to-provider": "filterRelationshipsConsumerToProvider",
    "provider-to-consumer": "filterRelationshipsProviderToConsumer",
}

PRIORITY_MAP = {
    "default": "default",
    "lowest_priority": "level1",
    "medium_priority": "level2",
    "highest_priority": "level3",
}

SERVICE_NODE_CONNECTOR_MAP = {
    "bd": {"id": "bd", "connector_type": "general"}
    # 'external_epg': {'id': 'externalEpg', 'connector_type': 'route-peering'}
}

YES_OR_NO_TO_BOOL_STRING_MAP = {"yes": "true", "no": "false"}

NDO_4_UNIQUE_IDENTIFIERS = ["templateID", "autoRouteTargetImport", "autoRouteTargetExport"]

NDO_API_VERSION_FORMAT = "/mso/api/{api_version}"
NDO_API_VERSION_PATH_FORMAT = "/mso/api/{api_version}/{path}"
