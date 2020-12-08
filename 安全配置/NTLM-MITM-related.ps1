# Disable 'Automatically detect proxy settings' in Internet Explorer.
function Disable-AutomaticallyDetectProxySettings
{
    # Read connection settings from Internet Explorer.
    $regKeyPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections\"
    $conSet = $(Get-ItemProperty $regKeyPath).DefaultConnectionSettings

    # Index into DefaultConnectionSettings where the relevant flag resides.
    $flagIndex = 8

    # Bit inside the relevant flag which indicates whether or not to enable automatically detect proxy settings.
    $autoProxyFlag = 8

    if ($($conSet[$flagIndex] -band $autoProxyFlag) -eq $autoProxyFlag)
    {
        # 'Automatically detect proxy settings' was enabled, adding one disables it.
        Write-Host "Disabling 'Automatically detect proxy settings'."
        $mask = -bnot $autoProxyFlag
        $conSet[$flagIndex] = $conSet[$flagIndex] -band $mask
        $conSet[4]++
        Set-ItemProperty -Path $regKeyPath -Name DefaultConnectionSettings -Value $conSet
    }

    $conSet = $(Get-ItemProperty $regKeyPath).DefaultConnectionSettings
    if ($($conSet[$flagIndex] -band $autoProxyFlag) -ne $autoProxyFlag)
    {
    	Write-Host "'Automatically detect proxy settings' is disabled."
    }
}

function Disable-Nbtns
{
    $QryNetAdapterConfigs = "Select * from Win32_NetworkAdapterConfiguration where IPEnabled = True"
    $NetAdapterConfigs = Get-WMIObject -query $QryNetAdapterConfigs

    $results = @()
    foreach ($adapter in $NetAdapterConfigs) {
        $thisResult = $adapter.SetTcpipNetbios(2)
        $results += [PSCustomObject]@{
            Description = $adapter.Description
            Result = $thisResult.ReturnValue
        }
    }

    Return $results
}

# 关闭代理自动配置
Disable-AutomaticallyDetectProxySettings
# Set-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoDetect" -value 0
Remove-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" "AutoDetect"

# 关闭多播名字解析
#New-Item "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Force
#Set-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast" -value 0
REG add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f

# 关闭NBT-NS解析
# $adapters=(gwmi win32_networkadapterconfiguration)
# Foreach ($adapter in $adapters){
#   Write-Host $adapter
#   $adapter.settcpipnetbios(2)
# }
Disable-Nbtns

# 关闭Intranet Zone的自动用户名密码认证
# https://support.microsoft.com/zh-cn/help/182569/internet-explorer-security-zones-registry-entries-for-advanced-users
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' -Name "1A00" | Set-ItemProperty -Name "1A00" -Value "0x00010000"
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\2' -Name "1A00" | Set-ItemProperty -Name "1A00" -Value "0x00010000"

# 禁用WPAD 使用hostcmd工具
.\hosts.exe add wpad. 255.255.255.255
# .\hosts.exe rem wpad.

# 禁用edge的NTLM认证
# HKCU\Software\Policies\Microsoft\Edge AuthSchemes basic,digest,negotiate
# HKLM\Software\Policies\Microsoft\Edge AuthSchemes basic,digest,negotiate

# 禁止NTLM认证
# HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0 RestrictSendingNTLMTraffic 00000002
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictReceivingNTLMTraffic /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v RestrictSendingNTLMTraffic /t REG_DWORD /d 2 /f
