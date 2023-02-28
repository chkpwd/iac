source "vsphere-iso" "winsrv22" {
	vm_name					      = "${var.vm_name}"
  notes                 = "Windows Server 2022 Desktop Experience. Built by Packer at ${timestamp()}."
  #guest_os_type         = "windows2019srvNext_64Guest" # VM version 18+
  guest_os_type         = "windows9_64Guest" # VM version 15
	vm_version				    = var.vm_version
	CPUs					        = var.vm_cpu_num_gui
	RAM						        = var.vm_mem_size_gui
	CPU_hot_plug			    = false
	RAM_hot_plug			    = true
	firmware				      = "efi"
	boot_order		        = "disk,cdrom"
	disk_controller_type	= ["lsilogic-sas"]
	usb_controller 			  = ["xhci"]

	network_adapters {
		network			        = var.network
		network_card        = "vmxnet3"
		passthrough		      = true
	}

  storage {
    disk_size             = var.vm_disk_size_gui
    disk_thin_provisioned = true
  }

  boot_wait             = "5s"
  boot_command	        = [
    "<leftCtrlOn><leftAltOn><del><leftCtrlOff><leftAltOff>",
    "<wait>",
    "<spacebar>"
  ]

	vcenter_server	    	= var.vcenter_server
	username		        	= var.vcenter_username
	password		        	= var.vcenter_password
	insecure_connection 	= true
	datacenter		      	= var.datacenter
	datastore		        	= var.datastore
	folder			        	= var.folder
	host				          = var.host
  cdrom_type            = "sata"

  cd_files              = [
    "${path.root}/files/Autounattend.xml",
    "${path.root}/files/Unattend-Sysprep.xml",
    "${path.root}/files/Patch.ps1",
    "${path.root}/files/Build.ps1",
    "${path.root}/files/Deploy.ps1",
    "${path.root}/files/Install-VMTools.ps1",
    "${path.root}/files/Install-OpenSSH.ps1",
    "${path.root}/files/ResetWinRM.ps1",
    "${path.root}/files/Sysprep.ps1",
    "${path.root}/files/TaskbarLayout.xml"
  ]

  iso_paths             = [
    # Windows ISO
    var.iso_path,
    # VMTools for Windows ISO
    "[] /usr/lib/vmware/isoimages/windows.iso"
  ]

  communicator          = "winrm"
  winrm_username        = var.winrm_username
  winrm_password        = var.winrm_password
  winrm_use_ntlm        = true
  winrm_use_ssl         = false
  winrm_timeout         = "15m"
  shutdown_command      = "powershell.exe -ExecutionPolicy Bypass -File C:\\Automation\\Packer\\Sysprep.ps1"
	remove_cdrom	        = true
  convert_to_template   = false
}

build {
  name    = var.vm_name
  sources = ["source.vsphere-iso.winsrv22"]
  provisioner "powershell" {
    scripts  = ["${path.root}/files/ResetWinRM-Task.ps1"]
  }
}
