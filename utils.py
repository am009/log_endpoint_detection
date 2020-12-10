from win10toast import ToastNotifier
import datetime
from dateutil import tz
import win32api, win32con, pywintypes

toaster = ToastNotifier()


def notification(title, content=''):
    if content == '':
        content = title
    toaster.show_toast(title,
                       content,
                       icon_path=None,
                       duration=5,
                       threaded=True)


def utc_to_local(evt_utc_time):
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    utc = datetime.datetime.strptime(evt_utc_time[:10] + ' ' + evt_utc_time[11:26], '%Y-%m-%d %H:%M:%S.%f')
    utc = utc.replace(tzinfo=from_zone)

    evt_local_time = utc.astimezone(to_zone)

    return evt_local_time


def get_filename(name):
    ind = name.rfind("\\") + 1
    return name[ind:]


def check_reg_symlink(reg_root, reg_path):
    # https://stackoverflow.com/questions/53009194/checking-if-registry-key-is-link-to-or-copy-of-another-one
    REG_OPTION_OPEN_LINK = 0x8
    reg_pri = win32con.KEY_READ
    try:
        key = win32api.RegOpenKeyEx(reg_root, reg_path, REG_OPTION_OPEN_LINK, reg_pri)
    except pywintypes.error as e:
        # (2, 'RegOpenKeyEx', 'The system cannot find the file specified.')
        # print(e.__dict__)
        # 'cannot find' or '找不到' in e.strerror
        # 根据系统语言的不同，返回的可能是中文也可能是英文，所以不做判断
        return False
    try:
        res = win32api.RegQueryValueEx(key, "SymbolicLinkValue")
    except pywintypes.error as e:
        # print(e)
        # 'cannot find' or '找不到' in e.strerror
        return False

    return res[1] == win32con.REG_LINK