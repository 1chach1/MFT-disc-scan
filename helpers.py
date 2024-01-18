import datetime


def parse_little_endian_signed_positive(buf):
    ret = 0
    for i, b in enumerate(buf):
        ret += b * (1 << (i * 8))
    return ret


def parse_little_endian_signed_negative(buf):
    ret = 0
    for i, b in enumerate(buf):
        ret += (b ^ 0xFF) * (1 << (i * 8))
    ret += 1

    ret *= -1
    return ret


def parse_little_endian_signed(buf):
    try:
        if not ord(buf[-1:]) & 0b10000000:
            return parse_little_endian_signed_positive(buf)
        else:
            return parse_little_endian_signed_negative(buf)
    except Exception:
        return ''


def get_time(windows_time):
    us = windows_time / 10
    return datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)


def get_fieldnames():
    return ['File_Name', 'Name_Length', 'Size_Data', 'Size_File_Name',
            'Created_Time', 'Modified_Time', 'Access_Time', 'MFT_Time',
            'File_Name_Created_Time', 'File_Name_Modified_Time', 'File_Name_Access_Time', 'File_Name_MFT_Time',
            'Non_Resident', 'Data_Runs']
