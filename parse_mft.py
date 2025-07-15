import sqlite3
import os

from structure_print import (
    read_struct, convert_windows_timestamp,
    ATTRIBUTE_HEADER_STRUCTURE, AttributeHeader,
    SI_FN_TIME_STRUCTURE, SIFNTime,
    MFT_ENTRY_HEADER, MFTEntryHeader,
    MFT_ENTRY_HEADER_SIZE,
    MFT_ENTRY_SIZE
)

def init_si_fn_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS si_fn (
            mft_entry INTEGER,
            si_create_time TEXT,
            si_modified_time TEXT,
            si_mft_modified_time TEXT,
            si_last_access_time TEXT,
            fn_create_time TEXT,
            fn_modified_time TEXT,
            fn_mft_modified_time TEXT,
            fn_last_access_time TEXT,
            is_timestomped BOOLEAN
        )
    ''')
    conn.commit()

def insert_buffered_records(conn, buffer):
    if not buffer:
        return

    cursor = conn.cursor()
    cursor.executemany('''
        INSERT INTO si_fn (
            mft_entry,
            si_create_time,
            si_modified_time,
            si_mft_modified_time,
            si_last_access_time,
            fn_create_time,
            fn_modified_time,
            fn_mft_modified_time,
            fn_last_access_time,
            is_timestomped
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', buffer)
    conn.commit()


def parse_mft(mftfile, mftfile_path, utc_offset, log_record_db_path):
    conn = sqlite3.connect(log_record_db_path)
    try:
        init_si_fn_db(conn)

        buffer = []
        buffer_limit = 100000

        max_number_of_mft_entry = os.path.getsize(mftfile_path) // MFT_ENTRY_SIZE
        current_mft_entry = 0

        while current_mft_entry < max_number_of_mft_entry:
            mftfile.seek(current_mft_entry * MFT_ENTRY_SIZE)
            mft_entry_header = read_struct(mftfile, MFT_ENTRY_HEADER, MFTEntryHeader)  # Address of STANDARD_INFORMATION
            if mft_entry_header.signature == 0x454C4946 and mft_entry_header.flags & 0x01:  # MTF Entry in useed
                si_attribute_header = read_struct(mftfile, ATTRIBUTE_HEADER_STRUCTURE, AttributeHeader)
                if (si_attribute_header.attr_type == 0x10):
                    if si_attribute_header.resident_flag == 0x00:
                        si_times = read_struct(mftfile, SI_FN_TIME_STRUCTURE, SIFNTime)
                    elif si_attribute_header.resident_flag == 0x40:
                        mftfile.seek(0x28, 1)
                        si_times = read_struct(mftfile, SI_FN_TIME_STRUCTURE, SIFNTime)

                mftfile.seek(current_mft_entry * MFT_ENTRY_SIZE + MFT_ENTRY_HEADER_SIZE + si_attribute_header.attr_length)  # Address of FILE_NAME
                fn_attribute_header = read_struct(mftfile, ATTRIBUTE_HEADER_STRUCTURE, AttributeHeader)
                if (fn_attribute_header.attr_type == 0x30):
                    if fn_attribute_header.resident_flag == 0x00:
                        mftfile.seek(0x08, 1)
                        fn_times = read_struct(mftfile, SI_FN_TIME_STRUCTURE, SIFNTime)
                    elif fn_attribute_header.resident_flag == 0x40:
                        mftfile.seek(0x30, 1)
                        fn_times = read_struct(mftfile, SI_FN_TIME_STRUCTURE, SIFNTime)

                is_si_newer = (
                    si_times.creation_time     > fn_times.creation_time and
                    si_times.mft_modified_time > fn_times.mft_modified_time and
                    si_times.modified_time     > fn_times.modified_time and
                    si_times.access_time       > fn_times.access_time
                )

                if is_si_newer:
                    record = (
                        current_mft_entry,
                        convert_windows_timestamp(si_times.creation_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(si_times.modified_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(si_times.mft_modified_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(si_times.access_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(fn_times.creation_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(fn_times.modified_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(fn_times.mft_modified_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        convert_windows_timestamp(fn_times.access_time.to_bytes(8, 'little').hex(), utc=utc_offset),
                        True
                    )
                    buffer.append(record)

                    if len(buffer) >= buffer_limit:
                        insert_buffered_records(conn, buffer)
                        buffer = []

            current_mft_entry += 1

        insert_buffered_records(conn, buffer)

    finally:
        conn.close()
    