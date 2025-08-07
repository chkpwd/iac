variable "machine_name" {
  type    = string
  default = ""
}

variable "os_version" {
  type    = string
  default = ""
}

variable "os_family" {
  type    = string
  default = ""
}

variable "os_iso_path" {
  type    = string
  default = ""
}

variable "iso_checksum" {
  type    = string
  default = ""
}

variable "boot_command" {
  type    = list(string)
  default = []
}

variable "ballooning_minimum" {
  type    = string
  default = "0"
}

variable "bios" {
  type    = string
  default = "ovmf"
}

variable "cd_files" {
  type = list(string)
  default = []
}

variable "cores" {
  type    = string
  default = "2"
}

variable "disable_kvm" {
  type    = bool
  default = false
}

variable "insecure_skip_tls_verify" {
  type    = bool
  default = true
}

variable "machine" {
  type    = string
  default = "q35"
}

variable "memory" {
  type    = string
  default = "4096"
}

variable "network_adapters" {
  type = object({
    bridge      = string
    model       = string
    firewall    = bool
    mac_address = string
    vlan_tag    = string
  })
  default = {
    bridge      = "vmbr0"
    model       = "virtio"
    firewall    = false
    mac_address = ""
    vlan_tag    = ""
  }
}

variable "proxmox_node" {
  type    = string
  default = "pve-srv-01"
}

variable "qemu_agent" {
  type    = bool
  default = true
}

variable "sockets" {
  type    = string
  default = "1"
}

variable "sysprep_unattended" {
  type    = string
  default = ""
}

variable "task_timeout" {
  type    = string
  default = "15m"
}

variable "winrm_username" {
  type = string
  default = "root"
}

variable "winrm_password" {
  type = string
  sensitive = true
  default = "password"
}

variable "winrm_port" {
  type = number
  default = 22
}

variable "vga" {
    type = object({
      type = string
      memory = string
    })
    default = {
      type = "std"
      memory = "256"
    }
  }

variable "virtio_iso_file" {
  type    = string
  default = "proxmox-iso:iso/virtio-win-0.1.248.iso"
}

variable "use_efi" {
  type    = bool
  default = false
}

variable "tags" {
  type = string
  default = "packer;uefi;template"
}
