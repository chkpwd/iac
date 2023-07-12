#!powershell

# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2018, Simon Baerlocher <s.baerlocher@sbaerlocher.ch>
# Copyright: (c) 2018, ITIGO AG <opensource@itigo.ch>
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

#Requires -Module Ansible.ModuleUtils.ArgvParser
#Requires -Module Ansible.ModuleUtils.CommandUtil

#AnsibleRequires -CSharpUtil Ansible.Basic

#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Common
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Config
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Sources
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Features
#AnsibleRequires -PowerShell ansible_collections.chocolatey.chocolatey.plugins.module_utils.Packages

[Diagnostics.CodeAnalysis.SuppressMessageAttribute(
    'PSUseConsistentWhitespace',
    '',
    Justification = 'Relax whitespace rule for better readability in module spec',
    Scope = 'function',
    # Apply suppression specifically to module spec
    Target = 'Get-ModuleSpec')]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

# Documentation: https://docs.ansible.com/ansible/2.10/dev_guide/developing_modules_general_windows.html#windows-new-module-development
function Get-ModuleSpec {
    @{
        options             = @{}
        supports_check_mode = $true
    }
}

$spec = Get-ModuleSpec

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
Set-ActiveModule $module

$chocoCommand = Get-ChocolateyCommand

$module.Result.ansible_facts = @{
    ansible_chocolatey = @{
        config = @{}
        feature = @{}
        sources = @()
        packages = @()
        outdated = @()
    }
}

$chocolateyFacts = $module.Result.ansible_facts.ansible_chocolatey
$chocolateyFacts.config = Get-ChocolateyConfig -ChocoCommand $chocoCommand
$chocolateyFacts.feature = Get-ChocolateyFeature -ChocoCommand $chocoCommand
$chocolateyFacts.sources = @(Get-ChocolateySource -ChocoCommand $chocoCommand)
$chocolateyFacts.packages = @(Get-ChocolateyPackage -ChocoCommand $chocoCommand)
$chocolateyFacts.outdated = @(Get-ChocolateyOutdated -ChocoCommand $chocoCommand)

# Return result
$module.ExitJson()
