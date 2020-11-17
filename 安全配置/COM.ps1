#define T_CLSID_ColorDataProxy               L"{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}"
#define T_CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define T_CLSID_FwCplLua                     L"{752438CB-E941-433F-BCB4-8B7D2329F0C8}"
#define T_CLSID_FileOperation                L"{3AD05575-8857-4850-9277-11B85BDB8E09}"
#define T_CLSID_ShellSecurityEditor          L"{4D111E08-CBF7-4f12-A926-2C7920AF52FC}"
#define T_CLSID_EditionUpgradeManager        L"{17CCA47D-DAE5-4E4A-AC42-CC54E28F334A}"
#define T_CLSID_IEAAddonInstaller            L"{BDB57FF2-79B9-4205-9447-F5FE85F37312}"
#define T_CLSID_SecurityCenter               L"{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}"
# ICMLuaUtil
#Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -Force
# IColorDataProxy
#Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}" -Force
# IFileOperation
#Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\{3ad05575-8857-4850-9277-11b85bdb8e09}" -Force
# ISecurityEditor
#Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\{4D111E08-CBF7-4f12-A926-2C7920AF52FC}" -Force
# T_CLSID_IEAAddonInstaller 测试大小写
#Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\{bdb57ff2-79b9-4205-9447-f5fe85f37312}" -Force
# T_CLSID_SecurityCenter
#Remove-Item "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}" -Force

Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\" "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}" -value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\" "{D2E7041B-2927-42fb-8E9F-7CE93B6DC937}" -value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\" "{3ad05575-8857-4850-9277-11b85bdb8e09}" -value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\" "{4D111E08-CBF7-4f12-A926-2C7920AF52FC}" -value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\" "{bdb57ff2-79b9-4205-9447-f5fe85f37312}" -value 0
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\UAC\COMAutoApprovalList\" "{E9495B87-D950-4AB5-87A5-FF6D70BF3E90}" -value 0