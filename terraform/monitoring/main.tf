locals {
  folder_names = ["games", "infrastructure", "kubernetes", "media"]
}

resource "grafana_contact_point" "discord" {
  name = "discord"

  slack {
    url   = "${data.sops_file.grafana-secrets.data["discord_alert_webhook"]}/slack"
    title = file("${path.root}/files/slack_title.tmpl")
    text  = file("${path.root}/files/slack_body.tmpl")
  }
}

resource "grafana_notification_policy" "default" {
  contact_point = grafana_contact_point.discord.name
  group_by = ["..."]
  group_wait      = "30s"
  group_interval  = "5m"
}

resource "grafana_folder" "main" {
  for_each = toset(local.folder_names)

  title = each.value
}
