resource "grafana_dashboard" "opnsense-docker-exporter" {
  config_json = file("files/dashboards/opnsense-docker-exporter.json")
  folder      = grafana_folder.main["infrastructure"].id
}

resource "grafana_dashboard" "opnsense-builtin-exporter" {
  config_json = file("files/dashboards/opnsense-builtin-exporter.json")
  folder      = grafana_folder.main["infrastructure"].id
}

resource "grafana_dashboard" "apex-legends-exporter" {
  config_json = file("files/dashboards/apex-legends-exporter.json")
  folder      = grafana_folder.main["games"].id
}

resource "grafana_dashboard" "kubernetes-longhorn" {
  config_json = file("files/dashboards/kubernetes-longhorn.json")
  folder      = grafana_folder.main["kubernetes"].id
}

resource "grafana_dashboard" "kubernetes-api-server" {
  config_json = file("files/dashboards/kubernetes-api-server.json")
  folder      = grafana_folder.main["kubernetes"].id
}

resource "grafana_dashboard" "kubernetes-global" {
  config_json = file("files/dashboards/kubernetes-global.json")
  folder      = grafana_folder.main["kubernetes"].id
}

resource "grafana_dashboard" "kubernetes-namespaces" {
  config_json = file("files/dashboards/kubernetes-namespaces.json")
  folder      = grafana_folder.main["kubernetes"].id
}

resource "grafana_dashboard" "kubernetes-nodes" {
  config_json = file("files/dashboards/kubernetes-nodes.json")
  folder      = grafana_folder.main["kubernetes"].id
}

resource "grafana_dashboard" "kubernetes-pods" {
  config_json = file("files/dashboards/kubernetes-pods.json")
  folder      = grafana_folder.main["kubernetes"].id
}

resource "grafana_dashboard" "kubernetes-prometheus" {
  config_json = file("files/dashboards/kubernetes-prometheus.json")
  folder      = grafana_folder.main["kubernetes"].id
}
