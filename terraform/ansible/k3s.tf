#===============================================================================
# Ansible Resources
#===============================================================================

# resource "ansible_playbook" "playbook" {
#   groups     = ["docker_hosts"]
#   name       = "mirage"
#   playbook   = "/home/hyoga/code/boilerplates/ansible/playbooks/get_macaddress.yaml"
#   #replayable = true
#   #diff_mode  = true
#   vault_password_file = "/home/hyoga/code/boilerplates/ansible/vault-password"
# } 

resource "ansible_group" "group" {
  name     = "k3s_cluster"
  children = ["master"]
}