#===============================================================================
# Ansible Resources
#===============================================================================

# resource "ansible_playbook" "playbook" {
#   groups     = ["docker_hosts"]
#   name       = "media-srv-01"
#   playbook   = "/home/chkpwd/code/iac/ansible/playbooks/get_macaddress.yaml"
#   #replayable = true
#   #diff_mode  = true
#   vault_password_file = "/home/chkpwd/code/iac/ansible/vault-password"
# } 

resource "ansible_group" "group" {
  name     = "k3s_cluster"
  children = ["master"]
}
