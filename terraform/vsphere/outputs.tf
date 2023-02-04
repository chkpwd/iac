# Output variable definitions

 output "vm_internal_address" {
   description = "IDs of the VPC's internal subnets"
   value       = module.test-vm.vsphere_virtual_machine.standalone.vm_name
}
