module "ansible-vm" {
 source      = "./modules/ansible-test"
 vm_count = 3
 ssh_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICsJocZS/OZ/4ZrLAxFOppiVMTym5oDkfHiir3YFg8mQ"
 vm_user = "hyoga"
 ip_address = "172.16.16.20"
 gateway = "172.16.16.1"
 bridge = "vmbr0"
 disk_size = 15
 cpu_count = 2
 ram_size = 2048
 storage_location = "Arenas"
 vlan_tag = "0"
 vm_name = "ansible-vm"
}

module "example-server-windowsvm-advanced" {
  source            = "Terraform-VMWare-Modules/vm/vsphere"
  version           = "3.5.0"
  dc                = "Datacenter"
  vmrp              = "cluster/Resources" # Works with ESXi/Resources
  vmfolder          = "Cattle"
  datastore_cluster = "Datastore Cluster" # You can use datastore variable instead
  vmtemp            = "TemplateName"
  instances         = 2
  vmname            = "AdvancedVM"
  vmnameformat      = "%03d" # To use three decimal with leading zero vmnames will be AdvancedVM001,AdvancedVM002
  domain            = "somedomain.com"
  network = {
    "Name of the Port Group in vSphere" = ["10.13.113.2", "10.13.113.3"] # To use DHCP create Empty list ["",""]; You can also use a CIDR annotation;
    "Second Network Card"               = ["", ""]
  }
  ipv4submask  = ["24", "8"]
  network_type = ["vmxnet3", "vmxnet3"]
  tags = {
    "terraform-test-category" = "terraform-test-tag"
  }
  data_disk = {
    disk1 = {
      size_gb                   = 30,
      thin_provisioned          = false,
      data_disk_scsi_controller = 0,
    },
    disk2 = {
      size_gb                   = 70,
      thin_provisioned          = true,
      data_disk_scsi_controller = 1,
      datastore_id              = "datastore-90679"
    }
  }
  scsi_bus_sharing = "physicalSharing" // The modes are physicalSharing, virtualSharing, and noSharing
  scsi_type        = "lsilogic"        // Other acceptable value "pvscsi"
  scsi_controller  = 0                 // This will assign OS disk to controller 0
  dns_server_list  = ["192.168.0.2", "192.168.0.1"]
  enable_disk_uuid = true
  vmgateway        = "192.168.0.1"
  auto_logon       = true
  run_once         = ["command01", "command02"] // You can also run Powershell commands
  orgname          = "Terraform-Module"
  workgroup        = "Module-Test"
  is_windows_image = true
  firmware         = "efi"
  local_adminpass  = "Password@Strong"
}
