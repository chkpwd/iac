#===============================================================================
# Fluxcd Resources
#===============================================================================

resource "flux_bootstrap_git" "kubernetes-cluster" {
  path = "./kubernetes/infrastructure"
  namespace = "flux-system"
  components_extra = [ "image-reflector-controller", "image-automation-controller" ]
}