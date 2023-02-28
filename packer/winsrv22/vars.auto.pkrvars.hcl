vm_name = "WinSrv22-template"
domain = "typhon.tech"

vcenter_server = "ronin.typhon.tech"

datacenter = "The Outlands"
datastore = "nvme-30A"
folder = "Templates"
host = "172.16.16.3" # * Change nodes name by removing from cluster
network = "Public"

vm_version = "15"

vm_cpu_num_core = "1"
vm_mem_size_core = "1024"
vm_disk_size_core = "40960"

vm_cpu_num_gui = "2"
vm_mem_size_gui = "4096"
vm_disk_size_gui = "40960"

winrm_username = "Administrator"
winrm_password = "DefaultPass@Packer"

iso_path = "[vsphere_nfs] template/iso/en-us_windows_server_2022_updated_feb_2023_x64_dvd_76afefb5.iso"
