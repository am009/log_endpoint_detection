from win10toast import ToastNotifier
import datetime
from dateutil import tz

toaster = ToastNotifier()


def notification(title,content=''):
    if content == '':
        content = title
    toaster.show_toast(title,
                   content,
                   icon_path=None,
                   duration=5,
                   threaded=True)

def Utc_to_local(evt_utc_time):
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    utc = datetime.datetime.strptime(evt_utc_time[:10] + ' ' + evt_utc_time[11:26], '%Y-%m-%d %H:%M:%S.%f')
    utc = utc.replace(tzinfo=from_zone)

    evt_local_time = utc.astimezone(to_zone)

    return evt_local_time


def get_filename(name):
    ind = name.rfind("\\") + 1
    return name[ind:]
