source "null" "testing" {
  ssh_host = "host"
  ssh_username = "username"
  ssh_password = "somepass"
}

build {
  sources = [
    "source.null.testing"
  ]

  provisioner "ansible" {
    playbook_file           = "../../ansible/playbooks/packer.yaml"
    use_proxy               = false
    max_retries             = 3
    inventory_file_template = "{{ .hostalias }} ansible_host={{ .host }} ansible_user={{ .user }} ansible_password={{ .password }} ansible_become_password={{ .password }}"
    ansible_env_vars        = [
      "ansible_config=../../ansible/ansible.cfg",
      "ansible_host_key_checking=false",
      "ansible_verbosity=2"
    ]
  }
}
