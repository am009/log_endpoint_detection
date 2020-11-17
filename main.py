import win32evtlog # requires pywin32 pre-installed
import win32con
import win32event
import datetime
from dateutil import tz
from utils import notification
import win32api
import msvcrt

import sys

import threading
import time

import re
import json
import os
import codecs

from event_filter import event_main_filter

def print_event_class(event):
    print ('Event Category:', event.EventCategory)
    print ('Time Generated:', event.TimeGenerated)
    print ('Source Name:', event.SourceName)
    print ('Event ID:', event.EventID)
    print ('Event Type:', event.EventType)
    data = event.StringInserts
    if data:
        print ('Event Data:')
        for msg in data:
            print (msg)
    print()

def print_event(event):
    record = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
    print(record)

def get_last_days_history(days,callback_func=print_event):

    count = 0

    print("Get last "+str(days)+" days history...")

    today_time = datetime.datetime.now(tz.tzlocal())

    path = "Microsoft-Windows-Sysmon/Operational"
    handle = win32evtlog.EvtQuery( # Get event log
                path,
                win32evtlog.EvtQueryReverseDirection,
                #"Event/System[EventID=5]",
                #None
            )

    while 1:
        events = win32evtlog.EvtNext(handle, 10)
        if len(events) == 0:
            # remove parsed events
            # win32evtlog.ClearEventLog(handle, None): Access Violation (0xC0000005)
            print("done")
            break
        for event in events:
            count += 1
            print_event(event)
            if count % 1000 == 0:
                print(count)

# 回调函数参数是日志的handle
# 坑人的地方在于不把事件拿干净就不会来新的事件通知，导致死锁等待
def register_listener(callback_func=print_event):
    query_text = "*"
    channel_path = "Microsoft-Windows-Sysmon/Operational"
    h_evt = win32event.CreateEvent(None, 0, 0, None)

    h_sub = win32evtlog.EvtSubscribe(
                channel_path,
                win32evtlog.EvtSubscribeToFutureEvents,
                SignalEvent=h_evt,
                Query=query_text
            )
    print("开始监听可疑事件")
    while True:
        while True:
            events=win32evtlog.EvtNext(h_sub, 10)
            if len(events)==0:
                break
            # print('retrieved %s events' %len(events))
            for event in events:
                callback_func(event)
        while True:
            # print ('waiting...')
            w=win32event.WaitForSingleObjectEx(h_evt, 2000, True)
            if w==win32con.WAIT_OBJECT_0:
                break
    # 垃圾回收的时候自动关闭句柄

from utils import get_filename
if __name__ == '__main__':
    # get_last_days_history(0.5)
    # notification('ttt', 'cont')
    register_listener(event_main_filter)
    print('程序退出')
