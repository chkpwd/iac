resource "prowlarr_indexer" "usenet_nzbgeek" {
  enable          = true
  name            = "NZBGeek"
  implementation  = "Newznab"
  config_contract = "NewznabSettings"
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

resource "prowlarr_indexer" "torrent_animetosho" {
  enable          = true
  name            = "AnimeTosho"
  implementation  = "Torznab"
  config_contract = "TorznabSettings"
  protocol        = "torrent"
  priority        = 25
  tags            = []

  fields = [
    {
      name: "baseUrl",
      text_value: "https://feed.animetosho.org"
    },
    {
      name: "apiPath"
      text_value: "/api"
    },
    {
      name: "apiKey"
      text_value: ""
    },
    {
      name: "vipExpiration"
      text_value: ""
    }
  ]
}

# resource "prowlarr_indexer" "usenet_drunkenslug" {
#   enable          = true
#   name            = "DrunkenSlug"
#   implementation  = "Newznab"
#   config_contract = "NewznabSettings"
#   protocol        = "usenet"
#   tags            = []

#   fields = [
#     {
#       name: "baseUrl",
#       text_value: "https://drunkenslug.com"
#     },
#     {
#       name: "apiPath"
#       text_value: "/api"
#     },
#     {
#       name: "apiKey"
#       text_value: "e983f92c8dfe05ac4de52b7cec85dfb2"
#     },
#     {
#       name: "grabLimit"
#       number_value: "20"
#     },
#     {
#       name: "queryLimit"
#       number_value: "20"
#     }
#   ]
# }