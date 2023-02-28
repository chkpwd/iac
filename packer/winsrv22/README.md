# Packer - Windows Server 2022 Template

Packer builds a Windows Server 2022 Core VM and a Windows Server 2022 Desktop Experience VM to a fairly default spec, per the configured spec in [pkr-winsrv22.pkr.hcl](pkr-winsrv22.pkr.hcl) and [vars.auto.pkrvars.hcl](vars.auto.pkrvars.hcl).

[Autounattend.xml](files/core/Autounattend.xml) configures base settings such as locale, language, computer name & credentials, installs VMware Tools, and more.  
Unattend also performs a single auto-login and executes [Deploy.ps1](files/Deploy.ps1), which is mostly self-documenting through comments. Most notably, it enables WinRM and **allows unencrypted traffic**, allowing Packer to continue to the next steps.

The next steps are:

* Restart the VM.
* Run [ResetWinRM-Task.ps1](files/ResetWinRM-Task.ps1) - This creates a scheduled task, triggered on startup, to run [ResetWinRM.ps1](files/ResetWinRM.ps1), which disallows unencrypted WinRM traffic, then unregisters the task and deletes itself and the unattend file leftover from sysprep.
* Run sysprep generalize.

## Build

1. Boot VM with [Autounattend](files/core/Autounattend.xml).
2. Run install.
3. Unattend specialize pass (locale/language, computer name, owner name/org, no join CEIP).
4. Unattend boots to audit mode.
5. Unattend runs [Install-VMTools](files/Install-VMTools.ps1).
6. Unattend sets admin password and one autologin.
7. Unattend runs [Build.ps1](files/Build.ps1) to patch the OS, copy deploy files, apply system-wide machine and user preferences, and configure network & WinRM.
8. Packer runs [ResetWinRM-Task](files/ResetWinRM-Task.ps1); this creates a schedule task to reset WinRM.
9. Packer runs the shutdown command. This executes [Sysprep.ps1](files/Sysprep.ps1).  
Aside from running sysprep generalize with [Unattend-Sysprep.xml](files/Unattend-Sysprep.xml), this script also tidies up sysprep's file(s) and process(es).

The VM is now built and ready to be cloned.

## Deploy

1. Boot VM with [Unattend-Sysprep](files/Unattend-Sysprep.xml).
2. Unattend specialize pass (allow RDP, no join CEIP).
3. Unattend applies some system-wide OOBE-based settings.
4. Unattend sets one autologin.
5. Unattend runs [Deploy.ps1](files/Deploy.ps1) to apply updates and some minor preferences.
6. [Deploy.ps1](files/Deploy.ps1) runs [Install-OpenSSH.ps1](files/Install-OpenSSH.ps1).
7. Machine is rebooted by deploy script.  
This applies any installed updates and, most importantly, also exits audit mode, which (for an unknown reason, likely bad config somewhere) newly deployed machines boot into.

## TODO

* Enable task manager disk performance counters
* Host large files (i.e. langpacks) somewhere to speed up Packer's ISO creation & upload.
* Use W10Privacy to set & export customisations https://www.w10privacy.de/english-home
* Anything from here? https://github.com/vmware-samples/packer-examples-for-vsphere/blob/main/scripts/windows/windows-prepare.ps1

## Resources

<https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/how-configuration-passes-work?view=windows-11>  
<https://github.com/wimmatthyssen/Hyper-V-VM-Template>  
<https://github.com/StefanScherer/packer-windows>  
<https://github.com/getvpro/Build-Packer>  
<https://github.com/mwrock/packer-templates>  
<https://rzander.azurewebsites.net/modern-os-deployment-mosd/>  
