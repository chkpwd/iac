#===============================================================================
# VMware vSphere configuration
#===============================================================================

# vCenter IP or FQDN #
vsphere_vcenter = "ronin.local.chkpwd.com"

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
vm_name = "deb-x12-terraform"

# The datastore name used to store the files of the virtual machine #
vm_datastore = "nvme-30A"

# The vSphere network name used by the virtual machine #
vm_network = "LAN"

# The domain name used by the virtual machine #
vm_domain = ""

folder_id = "cattles"
