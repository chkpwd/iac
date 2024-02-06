resource "grafana_rule_group" "main" {
  name             = "Game Servers"
  folder_uid       = "f07f5d58-91c0-407f-8cbd-0d541c6077f2"
  interval_seconds = 60

  rule {
    name      = "K8S - Check Palworld Game Server Status"
    condition = "B"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = grafana_data_source.k8s-prometheus.uid
      model = jsonencode({
        editorMode = "code",
        expr = "kube_pod_container_status_running{pod=~\"palworld-server-.+\"}",
        instant = true,
        intervalMs = 1000,
        legendFormat = "__auto",
        maxDataPoints = 43200,
        range = false,
        refId = "A"
      })
    }
    data {
      ref_id = "B"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "__expr__"
      model = jsonencode({
        conditions = [
          {
            evaluator = {
              params = [1]
              type   = "lt"
            }
            operator = {
              type = "and"
            }
            query = {
              params = ["C"]
            }
            reducer = {
              params = []
              type   = "last"
            }
            type = "query"
          }
        ]
        datasource = {
          type = "__expr__"
          uid  = "__expr__"
        }
        expression     = "A"
        intervalMs     = 1000
        maxDataPoints  = 43200
        refId          = "B"
        type           = "threshold"
      })
    }

    no_data_state  = "Alerting"
    exec_err_state = "Error"
    for            = "5m"
    annotations = {
      summary = "Palworld Server Status"
    }
    is_paused = false
  }
}
