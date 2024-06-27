resource "prowlarr_indexer" "usenet_nzbgeek" {
  enable          = true
  name            = "NZBgeek"
  implementation  = "Newznab"
  config_contract = "NewznabSettings"
  app_profile_id  = 1
  protocol        = "usenet"
  priority        = 1
  tags            = []

  fields = [
    {
      name       = "baseUrl",
      text_value = "https://api.nzbgeek.info"
    },
    {
      name       = "apiPath"
      text_value = "/api"
    },
    {
      name            = "apiKey"
      sensitive_value = data.external.bws_lookup.result["infra-media-secrets_nzbgeek_api_key"]
    },
    {
      name       = "vipExpiration"
      text_value = "2029-04-01"
    },
    {
      name         = "baseSettings.limitsUnit"
      number_value = 0
    }
  ]
}
