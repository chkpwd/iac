
resource "talos_machine_secrets" "machine_secrets" {
}

resource "talos_machine_configuration_controlplane" "controller" {
  count              = var.controller_count
  cluster_name       = var.cluster_name
  cluster_endpoint   = local.cluster_endpoint
  machine_secrets    = talos_machine_secrets.machine_secrets.machine_secrets
  kubernetes_version = local.kubernetes_version
  config_patches = [
    yamlencode(local.common_machine_config),
    yamlencode({
      machine = {
        install = {
          disk = "/dev/sda"
        }
        network = {
          hostname = local.controller_nodes[count.index].name
          interfaces = [
            {
              interface = "eth0"
              dhcp      = false
              addresses = ["${local.controller_nodes[count.index].address}/${local.netmask}"]
              routes = [
                {
                  network = "0.0.0.0/0"
                  gateway = local.gateway
                }
              ]
              vip = {
                ip = local.cluster_vip
              }
            }
          ]
          nameservers = local.nameservers
        }
        time = {
          servers = local.timeservers
        }
      }
    })
  ]
}

resource "talos_machine_configuration_worker" "worker" {
  count              = var.worker_count
  cluster_name       = var.cluster_name
  cluster_endpoint   = local.cluster_endpoint
  machine_secrets    = talos_machine_secrets.machine_secrets.machine_secrets
  kubernetes_version = local.kubernetes_version
  config_patches = [
    yamlencode(local.common_machine_config),
    yamlencode({
      machine = {
        install = {
          disk = "/dev/sda"
        }
        network = {
          hostname = local.worker_nodes[count.index].name
          interfaces = [
            {
              interface = "eth0"
              dhcp      = false
              addresses = ["${local.worker_nodes[count.index].address}/${local.netmask}"]
              routes = [
                {
                  network = "0.0.0.0/0"
                  gateway = local.gateway
                }
              ]
            }
          ]
          nameservers = local.nameservers
        }
        time = {
          servers = local.timeservers
        }
      }
    })
  ]
}

resource "talos_client_configuration" "talos" {
  cluster_name    = var.cluster_name
  machine_secrets = talos_machine_secrets.machine_secrets.machine_secrets
  endpoints       = [for n in local.controller_nodes : n.address]
}

resource "talos_machine_bootstrap" "talos" {
  talos_config = talos_client_configuration.talos.talos_config
  endpoint     = local.controller_nodes[0].address
  node         = local.controller_nodes[0].address
}

resource "talos_cluster_kubeconfig" "talos" {
  talos_config = talos_client_configuration.talos.talos_config
  endpoint     = local.controller_nodes[0].address
  node         = local.controller_nodes[0].address
}