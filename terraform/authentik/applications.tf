module "authentik-app-miniflux" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Miniflux"
  group  = "main"
  oauth2_values = {
    client_id         = "miniflux"
    client_secret     = data.external.bws_lookup.result["ns-tools-miniflux_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://miniflux.chkpwd.com/oauth2/oidc/callback",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/miniflux.webp"
    meta_description = "RSS Feed Reader"
  }

  access_group = {
    main = authentik_group.main.id
  }
}

module "authentik-app-mediamanager" {
  source = "../_modules/authentik/oauth2_app"
  name   = "MediaManager"
  group  = "main"
  oauth2_values = {
    client_id         = "mediamanager"
    client_secret     = data.external.bws_lookup.result["mediamanager_oidc_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://mediamanager.chkpwd.com/api/v1/auth/oauth/callback",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/mediamanager.webp"
    meta_description = "Media Management for Linux ISOs"
  }

  access_group = {
    main      = authentik_group.main.id
    secondary = authentik_group.secondary.id
  }
}

module "authentik-app-booklore" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Booklore"
  group  = "main"
  oauth2_values = {
    client_id         = "booklore"
    client_type       = "public"
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://booklore.chkpwd.com/oauth2-callback",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/booklore.webp"
    meta_description = "Book management software"
  }

  access_group = {
    main      = authentik_group.main.id
    secondary = authentik_group.secondary.id
  }
}

module "authentik-app-karakeep" {
  source = "../_modules/authentik/oauth2_app"
  name   = "karakeep"
  group  = "main"
  oauth2_values = {
    client_id         = "karakeep"
    client_secret     = data.external.bws_lookup.result["ns-tools-karakeep_oauth_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://karakeep.chkpwd.com/api/auth/callback/custom",
      },
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/karakeep-light.webp"
    meta_description = "Bookmark Everything"
  }

  access_group = {
    main      = authentik_group.main.id,
    secondary = authentik_group.secondary.id
  }
}
