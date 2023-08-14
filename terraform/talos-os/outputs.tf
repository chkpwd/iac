output "talosconfig" {
  value     = talos_client_configuration.talos.talos_config
  sensitive = true
}

output "kubeconfig" {
  value     = talos_cluster_kubeconfig.talos.kube_config
  sensitive = true
}

output "controllers" {
  value = join(",", [for node in local.controller_nodes : node.address])
}

output "workers" {
  value = join(",", [for node in local.worker_nodes : node.address])
}