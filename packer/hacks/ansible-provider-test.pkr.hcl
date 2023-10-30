source "null" "testing" {
  ssh_host = "hosting-srv-01"
  ssh_username = "administrator"
  ssh_password = "testing"
}

build {
  sources = [
    "source.null.testing"
  ]

  provisioner "ansible" {
    playbook_file           = "../ansible/playbooks/packer.yaml"
    use_proxy               = false
    max_retries             = 3
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_password={{ .Password }} ansible_become_password={{ .Password }} ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no'"
    ansible_env_vars        = [
      "ANSIBLE_INVENTORY_ENABLED=ini",
      "ANSIBLE_CONFIG=../ansible/ansible.cfg",
      "ANSIBLE_HOST_KEY_CHECKING=false",
      "ANSIBLE_VERBOSITY=2"
    ]
  }
}

# packer build hacks/ansible-provider-test.pkr.hcl
