#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'category'
            Option = @{
                choices = 'distribution', 'security'
                type = 'str'
            }
            Attribute = 'GroupCategory'
            CaseInsensitive = $true
        }
        [PSCustomObject]@{
            Name = 'homepage'
            Option = @{ type = 'str' }
            Attribute = 'Homepage'
        }
        [PSCustomObject]@{
            Name = 'managed_by'
            Option = @{ type = 'str' }
            Attribute = 'ManagedBy'
        }
        [PSCustomObject]@{
            Name = 'members'
            Option = @{
                type = 'dict'
                options = @{
                    add = @{
                        type = 'list'
                        elements = 'str'
                    }
                    remove = @{
                        type = 'list'
                        elements = 'str'
                    }
                    set = @{
                        type = 'list'
                        elements = 'str'
                    }
                }
            }
            Attribute = 'member'
            New = {
                param($Module, $ADParams, $NewParams)

                $newMembers = @(
                    foreach ($actionKvp in $Module.Params.members.GetEnumerator()) {
                        if ($null -eq $actionKvp.Value -or $actionKvp.Key -eq 'remove') { continue }

                        $invalidMembers = [System.Collections.Generic.List[string]]@()

                        foreach ($m in $actionKvp.Value) {
                            $obj = Get-AnsibleADObject -Identity $m @ADParams |
                                Select-Object -ExpandProperty DistinguishedName
                            if ($obj) {
                                $obj
                            }
                            else {
                                $invalidMembers.Add($m)
                            }
                        }

                        if ($invalidMembers) {
                            $module.FailJson("Failed to find the following ad objects for group members: '$($invalidMembers -join "', '")'")
                        }
                    }
                )

                if ($newMembers) {
                    if (-not $NewParams.ContainsKey('OtherAttributes')) {
                        $NewParams.OtherAttributes = @{}
                    }
                    # The AD cmdlets don't like explicitly casted arrays, use
                    # ForEach-Object to get back a vanilla object[] to set.
                    $NewParams.OtherAttributes.member = $newMembers | ForEach-Object { "$_" }
                }
                $Module.Diff.after.members = @($newMembers | Sort-Object)
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                [string[]]$existingMembers = $ADObject.member

                $desiredState = @{}
                foreach ($actionKvp in $Module.Params.members.GetEnumerator()) {
                    if ($null -eq $actionKvp.Value) { continue }

                    $invalidMembers = [System.Collections.Generic.List[string]]@()

                    $dns = foreach ($m in $actionKvp.Value) {
                        $obj = Get-AnsibleADObject -Identity $m @ADParams |
                            Select-Object -ExpandProperty DistinguishedName
                        if ($obj) {
                            $obj
                        }
                        else {
                            $invalidMembers.Add($m)
                        }
                    }

                    if ($invalidMembers) {
                        $module.FailJson("Failed to find the following ad objects for group members: '$($invalidMembers -join "', '")'")
                    }

                    $desiredState[$actionKvp.Key] = @($dns)
                }

                $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase
                [string[]]$diffAfter = @()
                if ($desiredState.ContainsKey('set')) {
                    [string[]]$desiredMembers = $desiredState.set
                    $diffAfter = $desiredMembers

                    $toAdd = [string[]][System.Linq.Enumerable]::Except($desiredMembers, $existingMembers, $ignoreCase)
                    $toRemove = [string[]][System.Linq.Enumerable]::Except($existingMembers, $desiredMembers, $ignoreCase)

                    if ($toAdd -or $toRemove) {
                        if (-not $SetParams.ContainsKey('Replace')) {
                            $SetParams.Replace = @{}
                        }
                        $SetParams.Replace.member = $desiredMembers
                    }
                }
                else {
                    [string[]]$toAdd = @()
                    [string[]]$toRemove = @()
                    $diffAfter = $existingMembers

                    if ($desiredState.ContainsKey('add') -and $desiredState.add) {
                        [string[]]$desiredMembers = $desiredState.add
                        $toAdd = [string[]][System.Linq.Enumerable]::Except($desiredMembers, $existingMembers, $ignoreCase)
                        $diffAfter = [System.Linq.Enumerable]::Union($desiredMembers, $diffAfter, $ignoreCase)
                    }
                    if ($desiredState.ContainsKey('remove') -and $desiredState.remove) {

                        [string[]]$desiredMembers = $desiredState.remove
                        $toRemove = [string[]][System.Linq.Enumerable]::Intersect($desiredMembers, $existingMembers, $ignoreCase)
                        $diffAfter = [System.Linq.Enumerable]::Except($diffAfter, $desiredMembers, $ignoreCase)
                    }

                    if ($toAdd) {
                        if (-not $SetParams.ContainsKey('Add')) {
                            $SetParams.Add = @{}
                        }
                        $SetParams.Add.member = $toAdd
                    }
                    if ($toRemove) {
                        if (-not $SetParams.ContainsKey('Remove')) {
                            $SetParams.Remove = @{}
                        }
                        $SetParams.Remove.member = $toRemove
                    }
                }

                $Module.Diff.after.members = ($diffAfter | Sort-Object)
            }
        }
        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
        }
        [PSCustomObject]@{
            Name = 'scope'
            Option = @{
                choices = 'domainlocal', 'global', 'universal'
                type = 'str'
            }
            Attribute = 'GroupScope'
            CaseInsensitive = $true
        }
    )
    ModuleNoun = 'ADGroup'
    DefaultPath = {
        param($Module, $ADParams)

        $GUID_USERS_CONTAINER_W = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        $defaultNamingContext = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext

        Get-ADObject @ADParams -Identity $defaultNamingContext -Properties wellKnownObjects |
            Select-Object -ExpandProperty wellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_USERS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }
    PreAction = {
        param ($Module, $ADParams, $ADObject)

        if ($Module.Params.state -eq 'present' -and (-not $Module.Params.scope) -and (-not $ADObject)) {
            $Module.FailJson("scope must be set when state=present and the group does not exist")
        }
    }
    PostAction = {
        param($Module, $ADParams, $ADObject)

        if ($ADObject) {
            $Module.Result.sid = $ADObject.SID.Value
        }
        elseif ($Module.Params.state -eq 'present') {
            # Use dummy value for check mode when creating a new user
            $Module.Result.sid = 'S-1-5-0000'
        }
    }
}
Invoke-AnsibleADObject @setParams
