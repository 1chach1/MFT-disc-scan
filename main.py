import csv
import io
import sys
from argparse import ArgumentParser

import helpers
from parser import Parser, FileRecord

input_file_name, output_file_name = None, None

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('-i', '--inputfile', dest='input', default='input')
    parser.add_argument('-o', '--outputfile', dest='output', default='output.csv')

    args = parser.parse_args()

    try:
        f = open(args.input, "rb")
        parser = Parser(f, f.read())
    except OSError:
        print("Could not open input file!")
        sys.exit(1)

    if not parser.validate():
        print("No NTFS found!")
        sys.exit(1)

    mft_data = io.BytesIO(parser.get_mft_data())

    removed_files = []

    while True:
        record = mft_data.read(1024)

        if len(record) < 1024:
            break

        file_record = FileRecord(record)

        if file_record.flags == 0x00:
            info = file_record.get_file_info()
            if info.get('File_Name'):
                removed_files.append(info)

    if len(removed_files):
        with open(args.output, 'w', encoding='utf-8', newline='') as f:
            w = csv.DictWriter(f, fieldnames=helpers.get_fieldnames(), escapechar='\\')
            w.writeheader()
            for file in removed_files:
                w.writerow(file)

    f.close()
