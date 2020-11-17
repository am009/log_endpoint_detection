

import subprocess
import win32evtlog
import xmltodict
from utils import Utc_to_local, notification, get_filename

service_outlier_executables_history = {}

outlier_parents_of_cmd_history = {}

suspicious_parent = {}

events_by_id={i:[] for i in range(24)}

def event_main_filter(event):
    record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
    record_dict = xmltodict.parse(record)

    # UTC to Local Time
    evt_local_time = Utc_to_local(record_dict['Event']['System']['TimeCreated']['@SystemTime'])
    record_dict['Event']['System']['TimeCreated']['@SystemTime'] = evt_local_time

    temp_data = {}
    for data in record_dict['Event']['EventData']['Data']:
        if '#text' in data:
            temp_data[data['@Name']] = data['#text']
        elif data == None or data == 'None':
            temp_data = {}
        else:
            temp_data[data['@Name']] = None
    record_dict['Event']['EventData'] = temp_data

    evt_id = int(record_dict['Event']['System']['EventID'])

    if evt_id == 1:
        image = str(record_dict['Event']['EventData']['Image'])
        parent_image = str(record_dict['Event']['EventData']['ParentImage'])

        if parent_image == "C:\\Windows\\System32\\services.exe":
            service_outlier_executables_history[image] = 0

        if 'cmd.exe' in image:
            outlier_parents_of_cmd_history[parent_image] = 0
        # events_by_id[evt_id].append({'image': record_dict['Event']['EventData']['Image']})

        if 'ParentCommandLine' in record_dict['Event']['EventData']:
            # 'C:\\WINDOWS\\system32\\DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}':
            if '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}' in record_dict['Event']['EventData']['ParentCommandLine'].upper():
                print('COMICMLuaUtils-bypassUAC')
                print(record_dict['Event']['EventData']['ParentCommandLine'])
                notification('COMICMLuaUtils-bypassUAC Detected!')


    # if evt_id == 2:
    #     events_by_id[evt_id].append({'image': record_dict['Event']['EventData']['Image'],
    #                                     'target name': record_dict['Event']['EventData']['TargetFilename']})
    # SYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL [DriverLoad]
    if evt_id == 6:
        if record_dict['Event']['EventData']['Signature'] != 'Microsoft Windows':
            events_by_id[evt_id].append({'ImageLoaded': record_dict['Event']['EventData']['ImageLoaded'],
                                        'Signature': record_dict['Event']['EventData']['Signature']})
    # SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS [ImageLoad]
    if evt_id == 7:
        if record_dict['Event']['EventData']['Signature']!='Microsoft Windows':
            events_by_id[evt_id].append({'Image': record_dict['Event']['EventData']['Image'],
                                        'ImageLoaded': record_dict['Event']['EventData']['ImageLoaded']})
        # dotLocal 被劫持dll的加载
        current = events_by_id[evt_id][-1]
        if '.exe.local\\' in current['ImageLoaded'].lower():
            print("dotLocal DLL hijack detected")
            print(events_by_id[evt_id][-1])
            notification("dotLocal DLL hijack detected",'Image: {}\nLib: {}'
                        .format(current['Image'], current['ImageLoaded']))
    # SYSMON EVENT ID 8 : REMOTE THREAD CREATED [CreateRemoteThread]
    if evt_id == 8:
        events_by_id[evt_id].append({'SourceProcessId': record_dict['Event']['EventData']['SourceProcessId'],
                                     'SourceImage': record_dict['Event']['EventData']['SourceImage'],
                                     'TargetProcessId': record_dict['Event']['EventData']['TargetProcessId'],
                                     'TargetImage': record_dict['Event']['EventData']['TargetImage'],
                                     'StartAddress': record_dict['Event']['EventData']['StartAddress'],
                                     'StartModule': record_dict['Event']['EventData']['StartModule'],
                                     'StartFunction': record_dict['Event']['EventData']['StartFunction']})
        print("RemoteThreadCreate detected")
        print(events_by_id[evt_id][-1])
        notification("RemoteThreadCreate detected",'Source: {}\nTarget: {}'
                     .format(events_by_id[evt_id][-1]['SourceImage'], events_by_id[evt_id][-1]['TargetImage']))
    # SYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION [RegistryEvent]

    # SYSMON EVENT ID 11 : FILE CREATED [FileCreate]
    if evt_id == 11:
        events_by_id[evt_id].append({'ProcessId': record_dict['Event']['EventData']['ProcessId'],
                                     'Image': record_dict['Event']['EventData']['Image'],
                                     'TargetFilename': record_dict['Event']['EventData']['TargetFilename']})
        current = events_by_id[evt_id][-1]
        if '.exe.local\\' in current['TargetFilename'].lower():
            print("dotLocal DLL hijack file create!")
            print(events_by_id[evt_id][-1])
            notification("dotLocal DLL hijack file create!",'Image: {}\nFile: {}'
                        .format(current['Image'], current['TargetFilename']))

    if evt_id == 13:
        events_by_id[evt_id].append({'Image': record_dict['Event']['EventData']['Image'],
                                     'TargetObject': record_dict['Event']['EventData']['TargetObject']
                                     })
        current = events_by_id[evt_id][-1]
        # 打印出得到的注册表事件 - 调试用
        # print("Registry value set")
        # print(len(record_dict['Event']['EventData']['Details']))
        # print(record_dict['Event']['EventData']['Details'][:5])
        # print(type(record_dict['Event']['EventData']['Details']))
        # print(current)
        if '[Reflection.Assembly]::Load' in record_dict['Event']['EventData']['Details'] and \
                "[Microsoft.Win32.Registry]" in record_dict['Event']['EventData']['Details']:
            print("Fileless Attack - Living off the land.")
            print(current)
            notification("Fileless Attack!")

        if not record_dict['Event']['EventData']['TargetObject'].startswith('HKLM'):
            target = record_dict['Event']['EventData']['TargetObject']
            target = target[target.rfind('\\')+1:].lower()
            # 检测windir环境变量改变 - 检测部分通过windir劫持的UAC绕过方法
            if target == 'windir':
                print("Possible UACBypass: windir hijack!")
                print(current)
                notification("Possible UACBypass: windir hijack!")
            # 检测COR_ENABLE_PROFILING环境变量改变 - 检测部分通过C# profile的UAC绕过方法
            elif target.upper() == 'COR_ENABLE_PROFILING' or target.upper() == 'COR_PROFILER':
                print("Possible UACBypass: C# profile!")
                print(current)
                notification("Possible UACBypass: C# profile!")


        ind = current['TargetObject'].find("\\")
        ind = current['TargetObject'].find("\\", ind + 1) + 1
        # notification("Registry value set", 'Source: {}\nTarget: {}'
        #              .format(get_filename(current['Image']),
        #                      current['TargetObject'][ind:]))


