# resource is formatted to be "[type]" "[entity_name]" so in this case
# we are looking to create a proxmox_vm_qemu entity named test_server
resource "proxmox_vm_qemu" "debian-x11-bullseye" {

  count = var.vm_count # just want 1 for now, set to 0 and apply to destroy VM
  name = var.vm_name #count.index starts at 0, so + 1 means this VM will be named test-vm-1 in proxmox
  
  # Specify VMID for the cluster
  # Comment this to obtain the next available ID
  #vmid = "50${count.index + 1}"

  # Proxmox target node
  target_node = var.node

  # Clone machine info
  clone = var.template_name

  # VMs settings
  agent = 1
  os_type = "cloud-init"
  cores = var.cpu_count
  sockets = 1
  cpu = "kvm64"
  memory = var.ram_size
  scsihw = "virtio-scsi-pci"
  bootdisk = "scsi0"

  disk {
    slot = 0
    size = "${var.disk_size}G"
    type = "scsi"
    storage = var.storage_location
    iothread = 1
  }
  
  # Configure multiple NICs
  network {
    model = "virtio"
    bridge = var.bridge
    tag = var.vlan_tag
  }

  lifecycle {
    ignore_changes = [
      network,
    ]
  }
  
  # Cloud init options
  #cicustom = "user=local:snippets/cloud_init_deb10_vm-01.yml"
  #ipconfig0 = "ip=172.16.16.3${count.index + 1}/24,gw=172.16.16.1"
  ipconfig0 = "ip=${var.ip_address}/24,gw=${var.gateway}"

  # Establishes connection to be used by all
  # generic remote provisioners (i.e. file/remote-exec)
  connection {
    type     = "ssh"
    user     = var.vm_user
    host     = var.ip_address
    agent = false
    private_key = "${file("~/.ssh/id_rsa")}"
  }

  # Pull in Ansible Configurations 
  provisioner "remote-exec" {
    
      inline = [
        "curl -fsSL https://raw.githubusercontent.com/chkpwd/scripts/main/Proxmox/helloworld.sh | exec bash"
      ]
  }
 
  # SSH Keys settings
  sshkeys = <<EOF
  ${var.ssh_key}
  EOF
}
