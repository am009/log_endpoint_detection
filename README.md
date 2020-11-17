# log_endpoint_detection

sysmon是监测windows系统的重要工具。用好sysmon能监测到很大部分的攻击。

UAC绕过的监测虽然有些麻烦，但是还是可以做一些相关的防御的。而且很多恶意软件使用的也是网上流行的方法。

## 使用
1. 管理员身份执行安全配置目录下的powershell脚本
2. 下载sysmon，加载项目中的规则
```
C:\Users\test\Desktop\develop\Sysmon\Sysmon.exe -i C:\Users\test\Desktop\develop\log_endpoint_detection\config-tmp.xml
```
2. 安装python包
```
pip install pywin32 python-dateutil win10toast xmltodict
```
3. 管理员身份启动main.py
