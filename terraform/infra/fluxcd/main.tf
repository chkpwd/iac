#===============================================================================
# Fluxcd Resources
#===============================================================================

resource "flux_bootstrap_git" "kubernetes-cluster" {
  path = "kubernetes/infrastructure"
}