resource "prowlarr_indexer" "usenet_nzbgeek" {
  enable          = true
  name            = "NZBGeek"
  implementation  = "Newznab"
  config_contract = "NewznabSettings"
  app_profile_id  = 1
  protocol        = "usenet"
  priority        = 1
  tags            = []

  fields = [
    {
      name: "baseUrl",
      text_value: "https://api.nzbgeek.info"
    },
    {
      name: "apiPath"
      text_value: "/api"
    },
    {
      name: "apiKey"
      text_value: "${data.sops_file.servarr-secrets.data["nzbgeek_api_key"]}"
    },
    {
      name: "vipExpiration"
      text_value: "2024-04-01"
    }
  ]
}

resource "prowlarr_indexer" "usenet_drunkenslug" {
  enable          = false
  name            = "DrunkenSlug"
  implementation  = "Newznab"
  config_contract = "NewznabSettings"
  app_profile_id  = 1
  protocol        = "usenet"
  tags            = []

  fields = [
    {
      name: "baseUrl",
      text_value: "https://drunkenslug.com"
    },
    {
      name: "apiPath"
      text_value: "/api"
    },
    {
      name: "apiKey"
      text_value: "${data.sops_file.servarr-secrets.data["drunkenslug_api_key"]}"
    },
    {
      name: "grabLimit"
      number_value: "20"
    },
    {
      name: "queryLimit"
      number_value: "20"
    }
  ]
}
