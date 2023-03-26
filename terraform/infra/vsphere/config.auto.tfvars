#===============================================================================
# VMware vSphere configuration
#===============================================================================

# vCenter IP or FQDN #
vsphere_vcenter = "172.16.16.6"

# vSphere datacenter name where the infrastructure will be deployed #
vsphere_datacenter = "The Outlands"

# Skip the verification of the vCenter SSL certificate (true/false) #
vsphere_unverified_ssl = "true"

# vSphere cluster name where the infrastructure will be deployed #
vsphere_cluster = "Eduardo"

#===============================================================================
# Virtual machine parameters
#===============================================================================

# The name of the virtual machine #
vm_name = "deb-x11-terraform"

# The datastore name used to store the files of the virtual machine #
vm_datastore = "nvme-30A"

# The vSphere network name used by the virtual machine #
vm_network = "LAN"

# The IP address of the virtual machine #
vm_ip = "172.16.16.65"

# The netmask used to configure the network card of the virtual machine (example: 24) #
vm_netmask = "24"

# The network gateway used by the virtual machine #
vm_gateway = "172.16.16.1"

# The DNS server used by the virtual machine #
vm_dns = ["172.16.16.1"]

# The domain name used by the virtual machine #
vm_domain = "typhon.tech"

# The domain search list
dns_suffix = ["typhon.tech"]

# The vSphere template the virtual machine is based on #
vm_template = "deb-x11-template"

# Use linked clone (true/false)
vm_linked_clone = "false"

# The number of vCPU allocated to the virtual machine #
vm_cpu = "1"

# The amount of RAM allocated to the virtual machine #
vm_ram = "1024"

# The public key for the system
vm_public_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa crypto"

# The ssh username for the guest system
ssh_username = "hyoga"

vm_pri_disk_size = ""

vm_sec_disk_size = ""

os_type = "linux"

instance_count = "1"

folder_id = "cattles"