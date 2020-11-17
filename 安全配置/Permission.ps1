function Set-MyRegPermission ($target) {
    $acl = Get-Acl $target

    $person = [System.Security.Principal.NTAccount]"Administrators"
    $access = [System.Security.AccessControl.RegistryRights]"FullControl"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"None"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule( `
    $person,$access,$inheritance,$propagation,$type)
    $acl.ResetAccessRule($rule)

    $person = [System.Security.Principal.NTAccount]"Everyone"
    $access = [System.Security.AccessControl.RegistryRights]"ReadKey"
    $inheritance = [System.Security.AccessControl.InheritanceFlags]"None"
    $propagation = [System.Security.AccessControl.PropagationFlags]"None"
    $type = [System.Security.AccessControl.AccessControlType]"Allow"
    $rule = New-Object System.Security.AccessControl.RegistryAccessRule( `
    $person,$access,$inheritance,$propagation,$type)
    $acl.ResetAccessRule($rule)
    Set-Acl $target $acl

    $acl = Get-Acl $target
    $acl.SetAccessRuleProtection($true, $false)
    $me = [System.Security.Principal.NTAccount]"Administrators"
    $acl.SetOwner($me)
    Set-Acl $target $acl
}

#md HKCU:\Software\Testkey2
#Set-MyRegPermission HKCU:\Software\Testkey2
# #33 fodhelper.exe #62 computerdefaults.exe
New-Item "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-MyRegPermission HKCU:\Software\Classes\ms-settings\Shell\Open\command
# #53 sdclt.exe
New-Item "HKCU:\Software\Classes\Folder\Shell\Open\command" -Force
Set-MyRegPermission HKCU:\Software\Classes\Folder\Shell\Open\command
# #56 wsreset.exe
#New-Item "HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\Open\command" -Force
Set-MyRegPermission HKCU:\Software\Classes\AppX82a6gwre4fdg3bt635tn5ctqjf8msdd2\Shell\Open\command
# #61 slui.exe
New-Item "HKCU:\Software\Classes\Launcher.SystemSettings\Shell\Open\command" -Force
Set-MyRegPermission HKCU:\Software\Classes\Launcher.SystemSettings\Shell\Open\command

