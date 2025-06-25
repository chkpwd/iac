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
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-semaphore-ui" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Semaphore UI"
  group  = "main"
  oauth2_values = {
    client_id         = "semaphore"
    client_secret     = data.external.bws_lookup.result["infra-semaphore-secrets_oauth_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "https://semaphore.chkpwd.com/api/auth/oidc/authentik/redirect",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/semaphore-ui.webp"
    meta_description = "Task Runner"
  }
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-immich" {
  source = "../_modules/authentik/oauth2_app"
  name   = "Immich"
  group  = "main"
  oauth2_values = {
    client_id         = "immich"
    client_secret     = data.external.bws_lookup.result["ns-tools-immich_client_secret"]
    property_mappings = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = [
      {
        matching_mode = "strict",
        url           = "app.immich:///oauth-callback",
      },
      {
        matching_mode = "strict",
        url           = "https://immich.chkpwd.com/auth/login",
      },
      {
        matching_mode = "strict",
        url           = "https://immich.chkpwd.com/user-settings",
      }
    ]
  }
  app_values = {
    icon_url         = "https://cdn.jsdelivr.net/gh/selfhst/icons/webp/immich.webp"
    meta_description = "Photo Management"
  }
  access_group = [
    authentik_group.main.id,
    authentik_group.secondary.id
  ]
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
  access_group = [
    authentik_group.main.id,
    authentik_group.secondary.id
  ]
}

module "authentik-app-kasten-k10" {
  source = "../_modules/authentik/oauth2_app"
  name   = "kasten-k10"
  group  = "main"
  oauth2_values = {
    client_id             = "kasten-k10"
    client_secret         = data.external.bws_lookup.result["kasten-k10_oauth_client_secret"]
    property_mappings     = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = []
  }
  app_values = {
    icon_url         = ""
    meta_description = "Kasten K10"
  }
  access_group = [
    authentik_group.main.id
  ]
}

module "authentik-app-soundbored" {
  source = "../_modules/authentik/oauth2_app"
  name   = "soundbored"
  group  = "main"
  oauth2_values = {
    client_id             = "soundbored"
    client_secret         = data.external.bws_lookup.result["soundbored_oauth_client_secret"]
    property_mappings     = data.authentik_property_mapping_provider_scope.sources.ids
    allowed_redirect_uris = []
  }
  app_values = {
    icon_url         = ""
    meta_description = "Soundbored"
  }
  access_group = [
    authentik_group.main.id
  ]
}
