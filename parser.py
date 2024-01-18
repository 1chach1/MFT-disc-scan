import ctypes
import helpers
import struct


class Parser:
    def __init__(self, file, data):
        self.data = data
        self.file = file

        self.file_system_name = struct.unpack('<8s', data[3:11])[0]
        self.bytes_per_sector = struct.unpack('<H', data[11:13])[0]
        self.sectors_per_cluster = struct.unpack('<B', data[13:14])[0]
        self.mft_start = struct.unpack('<Q', data[48:56])[0]

        self.mft = self.get_mft()

    def get_mft_offset(self):
        return self.bytes_per_sector * self.sectors_per_cluster * self.mft_start

    def validate(self):
        return self.file_system_name == b'NTFS    '

    def get_mft(self):
        return FileRecord(self.data[self.get_mft_offset():])

    def get_mft_data(self):
        data_attr = self.mft.get_attr('data')

        if not data_attr:
            raise 'No data attribute in MFT'

        if data_attr.header.non_resident == 0:
            return data_attr.data

        dataruns_info = data_attr.dataruns_info

        prev_cluster = None
        prev_seek = 0
        full_data = b''

        self.file.seek(0)

        for length, cluster in dataruns_info:
            if prev_cluster is None:
                self.file.seek(cluster * self.bytes_per_sector * self.sectors_per_cluster)
                prev_seek = self.file.tell()
                full_data += self.file.read(length * self.bytes_per_sector * self.sectors_per_cluster)
                prev_cluster = cluster
            else:
                self.file.seek(prev_seek)
                self.file.seek(prev_seek + (cluster * self.bytes_per_sector * self.sectors_per_cluster))
                full_data += self.file.read(length * self.bytes_per_sector * self.sectors_per_cluster)
                prev_seek = self.file.tell()
                prev_cluster = cluster

        return full_data


class FileRecord:
    def __init__(self, data):
        self.magic = struct.unpack('<I', data[:4])[0]
        self.update_sequence_offset = struct.unpack('<H', data[4:6])[0]
        self.update_sequence_size = struct.unpack('<H', data[6:8])[0]
        self.lsn = struct.unpack('<d', data[8:16])[0]
        self.sequence_number = struct.unpack('<H', data[16:18])[0]
        self.hard_link_count = struct.unpack('<H', data[18:20])[0]
        self.attr_offset = struct.unpack('<H', data[20:22])[0]
        self.flags = struct.unpack('<H', data[22:24])[0]
        self.size = struct.unpack('<I', data[24:28])[0]
        self.alloc_size = struct.unpack('<I', data[28:32])[0]
        self.ref_num = struct.unpack('<Lxx', data[32:38])[0]
        self.ref_seq = struct.unpack('<H', data[38:40])[0]
        self.next_attr_id = struct.unpack('<H', data[40:42])[0]

        if self.update_sequence_offset == 42:
            self.sequence_attr_1 = data[44:46]
            self.sequence_attr_2 = data[46:58]
        else:
            self.sequence_attr_1 = data[50:52]
            self.sequence_attr_2 = data[52:54]

        self.attrs = self.get_attrs(data)

    def get_attrs(self, data):
        ptr = self.attr_offset
        attrs = []

        while ptr < 1024:
            attr = Attr(data[ptr:])

            if attr.type == 'end':
                break

            attrs.append(attr)

            if attr.header.length <= 0:
                break

            ptr += attr.header.length

        return attrs

    def get_attr(self, type):
        for attr in self.attrs:
            if attr.type == type:
                return attr
        return None

    def get_file_info(self):
        file_name = self.get_attr('file_name')
        standard_info = self.get_attr('standard_information')
        data_attr = self.get_attr('data')

        info = {}

        if file_name:
            info['File_Name'] = file_name.file_name
            info['Name_Length'] = file_name.file_name_length
            info['Size_File_Name'] = file_name.real_size_filename
            info['File_Name_Created_Time'] = helpers.get_time(file_name.time_created)
            info['File_Name_Modified_Time'] = helpers.get_time(file_name.time_modified)
            info['File_Name_Access_Time'] = helpers.get_time(file_name.time_accessed)
            info['File_Name_MFT_Time'] = helpers.get_time(file_name.time_mft)

        if standard_info:
            info['Created_Time'] = helpers.get_time(standard_info.time_created)
            info['Modified_Time'] = helpers.get_time(standard_info.time_modified)
            info['Access_Time'] = helpers.get_time(standard_info.time_accessed)
            info['MFT_Time'] = helpers.get_time(standard_info.time_mft)

        if data_attr:
            info['Size_Data'] = data_attr.real_size_data
            info['Non_Resident'] = data_attr.data_non_res
            if data_attr.data_non_res:
                info['Data_Runs'] = len(data_attr.dataruns_info)

        return info


class Attr:
    def __init__(self, data):
        self.header = AttrHeader(data)
        self.parse_attr(data)

    def parse_attr(self, data):
        data_orig = data
        if self.header.non_resident == 0:
            data = data[self.header.offset:self.header.offset + self.header.size]

        if self.header.type == 0x10:
            self.type = 'standard_information'

            self.time_created = struct.unpack('<Q', data[:8])[0]
            self.time_modified = struct.unpack('<Q', data[8:16])[0]
            self.time_mft = struct.unpack('<Q', data[16:24])[0]
            self.time_accessed = struct.unpack('<Q', data[24:32])[0]

        elif self.header.type == 0x20:
            self.type = 'attr_list'
        elif self.header.type == 0x30:
            self.type = 'file_name'

            self.time_created = struct.unpack('<Q', data[8:16])[0]
            self.time_modified = struct.unpack('<Q', data[16:24])[0]
            self.time_mft = struct.unpack('<Q', data[24:32])[0]
            self.time_accessed = struct.unpack('<Q', data[32:40])[0]

            self.real_size_filename = struct.unpack('<Q', data[48:56])[0]
            self.file_name_length = struct.unpack('<B', data[64:65])[0]
            self.file_name = data[66:66 + self.file_name_length * 2].decode('unicode_escape')
        elif self.header.type == 0x40:
            self.type = 'obj_id'
        elif self.header.type == 0x50:
            self.type = 'security_descr'
        elif self.header.type == 0x60:
            self.type = 'volume_name'
        elif self.header.type == 0x70:
            self.type = 'volume_info'
        elif self.header.type == 0x80:
            self.type = 'data'

            if self.header.non_resident == 0:
                self.data = data
                self.real_size_data = struct.unpack('<L', data_orig[16:20])[0]
                self.data_non_res = 0
            else:
                self.data_non_res = 1
                self.dataruns_info = self.header.get_dataruns_info()
                self.real_size_data = struct.unpack('<Q', data[48:56])[0]
        elif self.header.type == 0x90:
            self.type = 'index_root'
        elif self.header.type == 0xA0:
            self.type = 'index_alloc'
        elif self.header.type == 0xB0:
            self.type = 'bitmap'
        elif self.header.type == 0xC0:
            self.type = 'reparse_point'
        elif self.header.type == 0xD0:
            self.type = 'ea_info'
        elif self.header.type == 0xE0:
            self.type = 'ea'
        elif self.header.type == 0xF0:
            self.type = 'property_set'
        elif self.header.type == 0x100:
            self.type = 'logged_utility_stream'
        elif self.header.type == 0xffffffff:
            self.type = 'end'
        else:
            self.type = 'unknown'


class AttrHeader:
    def __init__(self, data):
        self.type = struct.unpack('<L', data[:4])[0]
        self.length = struct.unpack('<L', data[4:8])[0]
        self.non_resident = struct.unpack('B', data[8:9])[0]
        self.name_length = struct.unpack('B', data[9:10])[0]
        self.name_offset = struct.unpack('<H', data[10:12])[0]
        self.flags = struct.unpack('<H', data[12:14])[0]
        self.attr_id = struct.unpack('<H', data[14:16])[0]

        if self.non_resident == 0:
            self.size = struct.unpack('<L', data[16:20])[0]
            self.offset = struct.unpack('<H', data[20:22])[0]
            self.indexed_flag = struct.unpack('B', data[22:23])[0]
        else:
            self.vcn_start = struct.unpack('<Q', data[16:24])[0]
            self.vcn_last = struct.unpack('<Q', data[24:32])[0]
            self.datarun_offset = struct.unpack('<H', data[32:34])[0]
            self.compression_unit_size = struct.unpack('<H', data[34:36])[0]
            self.alloc_size = struct.unpack('<Lxxxx', data[40:48])[0]
            self.real_size = struct.unpack('<Lxxxx', data[48:56])[0]
            self.stream_size = struct.unpack('<Lxxxx', data[56:64])[0]
            self.dataruns = data[self.datarun_offset:self.length]

    def get_dataruns_info(self):
        result = []

        pos = 0
        prev_offset = 0

        c_uint8 = ctypes.c_uint8

        class LengthBits(ctypes.LittleEndianStructure):
            _fields_ = [
                ("lenlen", c_uint8, 4),
                ("offlen", c_uint8, 4),
            ]

        class Lengths(ctypes.Union):
            _fields_ = [("b", LengthBits),
                        ("asbyte", c_uint8)]

        lengths = Lengths()

        while True:
            lengths.asbyte = struct.unpack('B', self.dataruns[pos:pos + 1])[0]
            pos += 1

            if lengths.asbyte == 0x00:
                break

            length = helpers.parse_little_endian_signed(self.dataruns[pos:pos + lengths.b.lenlen])

            pos += lengths.b.lenlen

            if lengths.b.offlen > 0:
                offset = helpers.parse_little_endian_signed(self.dataruns[pos:pos + lengths.b.offlen])
                offset += prev_offset
                prev_offset = offset
                pos += lengths.b.offlen
            else:
                offset = 0
                pos += 1

            result.append([length, offset])

        return result
