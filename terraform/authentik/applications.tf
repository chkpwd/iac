module "authentik-app-miniflux" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Miniflux"
  group  = "main"
  oauth2_values = {
    client_id         = "miniflux"
    client_secret     = data.external.bws_lookup.result["miniflux_client_secret"]
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

  access_group = { main = authentik_group.main.id }
}

module "authentik-app-grimmory" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Grimmory"
  group  = "main"
  oauth2_values = {
    client_id         = "grimmory"
    client_type       = "public"
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://grimmory.chkpwd.com/oauth2-callback",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/grimmory.webp"
    meta_description = "Book management software"
  }

  access_group = { main = authentik_group.main.id }
}

module "authentik-app-karakeep" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Karakeep"
  group  = "main"
  oauth2_values = {
    client_id         = "karakeep"
    client_secret     = data.external.bws_lookup.result["karakeep_oauth_client_secret"]
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

  access_group = { main = authentik_group.main.id }
}

module "authentik-app-trek" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Trek"
  group  = "main"
  oauth2_values = {
    client_id         = "trek"
    client_secret     = data.external.bws_lookup.result["trek_oauth_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://trek.chkpwd.com/api/auth/oidc/callback",
      },
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/trek.webp"
    meta_description = "Travel Planning"
  }

  access_group = {
    main      = authentik_group.main.id
    secondary = authentik_group.secondary.id
  }
}

module "authentik-app-immich" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Immich"
  group  = "main"
  oauth2_values = {
    client_id         = "immich"
    client_secret     = data.external.bws_lookup.result["immich_oidc_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://immich.chkpwd.com/auth/login",
      },
      {
        matching_mode = "strict",
        url           = "https://immich.chkpwd.com/user-settings",
      },
      {
        matching_mode = "strict",
        url           = "app.immich:///oauth-callback",
      },
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/immich.webp"
    meta_description = "Self-Hosted Photo and Video Management"
  }

  access_group = {
    main      = authentik_group.main.id
    secondary = authentik_group.secondary.id
  }
}

module "authentik-app-sure" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Sure"
  group  = "main"
  oauth2_values = {
    client_id         = "sure"
    client_secret     = data.external.bws_lookup.result["sure_oidc_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://sure.chkpwd.com/api/auth/oidc/callback",
      },
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/sure.webp"
    meta_description = "Financial Management"
  }

  access_group = {
    main      = authentik_group.main.id
    secondary = authentik_group.secondary.id
  }
}
