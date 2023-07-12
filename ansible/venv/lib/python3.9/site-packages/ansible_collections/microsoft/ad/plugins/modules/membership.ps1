#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        dns_domain_name = @{
            type = 'str'
        }
        domain_admin_user = @{
            type = 'str'
        }
        domain_admin_password = @{
            no_log = $true
            type = 'str'
        }
        domain_ou_path = @{
            type = 'str'
        }
        hostname = @{
            type = 'str'
        }
        offline_join_blob = @{
            type = "str"
            no_log = $true
        }
        reboot = @{
            default = $false
            type = 'bool'
        }
        state = @{
            choices = 'domain', 'workgroup'
            required = $true
            type = 'str'
        }
        workgroup_name = @{
            type = 'str'
        }
    }
    mutually_exclusive = @(
        @('offline_join_blob', 'domain_admin_user'),
        @('offline_join_blob', 'dns_domain_name'),
        @('offline_join_blob', 'domain_ou_path'),
        @('offline_join_blob', 'hostname')
    )
    required_if = @(
        @('state', 'domain', @('domain_admin_user', 'offline_join_blob'), $true),
        @('state', 'workgroup', @('workgroup_name', 'domain_admin_user', 'domain_admin_password'))
    )
    required_together = @(
        , @('domain_admin_user', 'domain_admin_password')
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Diff.before = @{}
$module.Diff.after = @{}

$dnsDomainName = $module.Params.dns_domain_name
$domainCredential = if ($module.Params.domain_admin_user) {
    New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
        $module.Params.domain_admin_user,
        (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_admin_password)
    )
}
$domainOUPath = $module.Params.domain_ou_path
$hostname = $module.Params.hostname
$state = $module.Params.state
$workgroupName = $module.Params.workgroup_name

Add-CSharpType -AnsibleModule $module -References @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace microsoft.ad.membership
{
    [Flags]
    public enum ProvisionOptions
    {
        None = 0,
        NETSETUP_PROVISION_ONLINE_CALLER = 0x40000000,
    }

    public static class Native
    {
        [DllImport("Netapi32.dll", EntryPoint = "NetRequestOfflineDomainJoin")]
        private static extern int NativeNetRequestOfflineDomainJoin(
            IntPtr pProvisionBinData,
            int cbProvisionBinDataSize,
            int dwOptions,
            [MarshalAs(UnmanagedType.LPWStr)] string lpWindowsPath);

        public static void NetRequestOfflineDomainJoin(byte[] data, ProvisionOptions options,
            string windowsPath)
        {
            IntPtr buffer = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, buffer, data.Length);

                int res = NativeNetRequestOfflineDomainJoin(buffer, data.Length, (int)options, windowsPath);
                if (res != 0)
                {
                    throw new Win32Exception(res);
                }
            }
            finally {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
'@

Function Get-CurrentState {
    <#
    .SYNOPSIS
    Gets the current state of the host.
    #>
    [CmdletBinding()]
    param ()

    $cs = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain, PartOfDomain, Workgroup
    $domainName = if ($cs.PartOfDomain) {
        try {
            [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
        }
        catch [System.Security.Authentication.AuthenticationException] {
            # This might happen if running as a local user on a host already
            # joined to the domain. Just try the Win32_ComputerSystem fallback
            # value.
            $cs.Domain
        }
    }
    else {
        $null
    }

    [PSCustomObject]@{
        HostName = $env:COMPUTERNAME
        PartOfDomain = $cs.PartOfDomain
        DnsDomainName = $domainName
        WorkgroupName = $cs.Workgroup
    }
}

$currentState = Get-CurrentState

$module.Diff.before = @{
    dns_domain_name = $currentState.DnsDomainName
    hostname = $currentState.HostName
    state = if ($currentState.PartOfDomain) { 'domain' } else { 'workgroup' }
    workgroup_name = $currentState.WorkgroupName
}
if (-not $hostname) {
    $hostname = $currentState.HostName
}

if ($state -eq 'domain') {
    if ($module.Params.offline_join_blob) {
        # FUTURE: Read blob to see what domain it is for.
        if (-not $currentState.PartOfDomain) {
            try {
                if (-not $module.CheckMode) {
                    [microsoft.ad.membership.Native]::NetRequestOfflineDomainJoin(
                        [System.Convert]::FromBase64String($module.Params.offline_join_blob),
                        "NETSETUP_PROVISION_ONLINE_CALLER",
                        $env:SystemRoot)
                }
            }
            catch [System.ComponentModel.Win32Exception] {
                $msg = "Failed to perform offline domain join (0x{0:X8}): {1}" -f $_.Exception.NativeErrorCode, $_.Exception.Message
                $module.FailJson($msg, $_)
            }

            $module.Result.changed = $true
            $module.Result.reboot_required = $true
        }
    }
    else {
        if ($dnsDomainName -ne $currentState.DnsDomainName) {
            if ($currentState.PartOfDomain) {
                $module.FailJson("Host is already joined to '$($currentState.DnsDomainName)', switching domains is not implemented")
            }

            $joinParams = @{
                ComputerName = '.'
                Credential = $domainCredential
                DomainName = $dnsDomainName
                Force = $true
                WhatIf = $module.CheckMode
            }
            if ($hostname -ne $currentState.HostName) {
                $joinParams.NewName = $hostname

                # By setting this here, the Rename-Computer call is skipped as
                # joining the domain will rename the host for us.
                $hostname = $currentState.HostName
            }
            if ($domainOUPath) {
                $joinParams.OUPath = $domainOUPath
            }

            Add-Computer @joinParams

            $module.Result.changed = $true
            $module.Result.reboot_required = $true
        }
    }
}
else {
    if ($workgroupName -ne $currentState.WorkgroupName) {
        if ($currentState.PartOfDomain) {
            $removeParams = @{
                UnjoinDomainCredential = $domainCredential
                Workgroup = $workgroupName
                Force = $true
                WhatIf = $module.CheckMode
            }

            Remove-Computer @removeParams
        }
        elseif (-not $module.CheckMode) {
            try {
                $res = Get-CimInstance Win32_ComputerSystem | Invoke-CimMethod -MethodName JoinDomainOrWorkgroup -Arguments @{
                    Name = $workgroupName
                }
            }
            catch {
                $module.FailJson("Failed to set workgroup as '$workgroupName': $($_.Exception.Message)", $_)
            }

            if ($res.ReturnValue -ne 0) {
                $msg = [System.ComponentModel.Win32Exception]$res.ReturnValue
                $module.FailJson("Failed to set workgroup as '$workgroupName', return value: $($res.ReturnValue): $msg")
            }
        }

        $module.Result.changed = $true
        $module.Result.reboot_required = $true
    }
}

if ($hostname -ne $currentState.Hostname) {
    $renameParams = @{
        DomainCredential = $domainCredential
        NewName = $hostname
        WhatIf = $module.CheckMode
        Force = $true
    }
    Rename-Computer @renameParams

    $module.Result.changed = $true
    $module.Result.reboot_required = $true
}

$module.Diff.after = @{
    dns_domain_name = $dnsDomainName
    hostname = $hostname
    state = $state
    workgroup_name = $workgroupName
}

$module.ExitJson()
