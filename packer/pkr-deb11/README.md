# Packer - Debian 11 Template

Packer builds a Debian 11 VM to a fairly default spec, per the configured spec in [pkr-deb11.pkr.hcl](pkr-deb11.pkr.hcl) and [vars.auto.pkrvars.hcl](vars.auto.pkrvars.hcl). It does _not_ convert it to a template; this is handled later.

It then bootstraps it using the [debian-template](../../ansible/debian_template.yml) Ansible playbook.

After that, it runs [configure-template.ps1](files/configure-template.ps1) to set some advanced VMX settings.

Then it runs [clone-bootstrap.ps1](files/clone-bootstrap.ps1) which, in turn, executes multiple instances of [clone-vm.ps1](files/clone-vm.ps1) asynchronously to clone the built VM to other sites, configure the destination VM's network vNIC on the correct port group (network), and convert it to a template.  
Should this script fail at any point, it will revert to the previous state (i.e. copied VM is deleted and old template is restored in place).

Finally, it runs [finish-template.ps1](files/finish-template.ps1) to remove the former template, upgrade the hardware version and set the name of the new template-to-be, and finally convert it to a template.
