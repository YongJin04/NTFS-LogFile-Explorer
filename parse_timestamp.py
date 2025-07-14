from datetime import datetime, timezone, timedelta
import sqlite3
import struct
import os

def init_timestomp_db(conn):
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS TimeStomp (
            this_lsn INTEGER,
            undo_create_time TEXT,
            undo_modified_time TEXT,
            undo_mft_modified_time TEXT,
            undo_last_access_time TEXT,
            redo_create_time TEXT,
            redo_modified_time TEXT,
            redo_mft_modified_time TEXT,
            redo_last_access_time TEXT,
            is_timestomped BOOLEAN,
            attr_name TEXT,
            target_vcn INTEGER,
            cluster_number INTEGER,
            record_offset INTEGER,
            attr_offset INTEGER
        )
    ''')
    conn.commit()

def process_and_insert(conn, rows, utc_offset, attr):
    cursor = conn.cursor()
    for this_lsn, redo_hex, undo_hex, target_vcn, cluster_number, record_offset, attr_offset in rows:
        try:
            offset = int(attr_offset, 16)
        except ValueError:
            continue
        
        if attr == 'STANDARD_INFORMATION':
            undo_times = extract_timestamps_standard_information(undo_hex, offset, utc_offset)
            redo_times = extract_timestamps_standard_information(redo_hex, offset, utc_offset)
        elif attr == 'FILE_NAME':
            undo_times = extract_timestamps_file_name(undo_hex, offset, utc_offset)
            redo_times = extract_timestamps_file_name(redo_hex, offset, utc_offset)            

        is_timestomped = any(
            undo and redo and undo > redo
            for undo, redo in zip(undo_times, redo_times)
        )

        cursor.execute('''
            INSERT INTO TimeStomp (
                this_lsn,
                undo_create_time, undo_modified_time, undo_mft_modified_time, undo_last_access_time,
                redo_create_time, redo_modified_time, redo_mft_modified_time, redo_last_access_time,
                is_timestomped, attr_name,
                target_vcn, cluster_number, record_offset, attr_offset
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            this_lsn,
            *(t if t else None for t in undo_times),
            *(t if t else None for t in redo_times),
            is_timestomped, attr,
            target_vcn, cluster_number, record_offset, attr_offset
        ))
    conn.commit()

def fetch_relevant_rows_standard_information(conn):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT this_lsn, redo_data, undo_data, target_vcn, cluster_number, record_offset, attr_offset
        FROM LogFile
        WHERE record_offset = "0x38"
        AND redo_op_value = "0x7"
        AND undo_op_value = "0x7"
        AND attr_offset IN ("0x18", "0x20", "0x28", "0x30")
    ''')
    return cursor.fetchall()

def fetch_relevant_rows_file_name(conn):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT this_lsn, redo_data, undo_data, target_vcn, cluster_number, record_offset, attr_offset
        FROM LogFile
        WHERE record_offset = "0x98"
        AND redo_op_value = "0x7"
        AND undo_op_value = "0x7"
        AND attr_offset IN ("0x18", "0x20", "0x28", "0x30", "0x38")
    ''')
    return cursor.fetchall()

def extract_timestamps_standard_information(data_hex: str, attr_offset: int, utc: int):
    times = [None] * 4

    field_map = {
        0x18: [0, 1, 2, 3],       # Created, Modified, MFT-Modified, Last-Access
        0x20: [1, 2, 3],          # Modified, MFT-Modified, Last-Access
        0x28: [2, 3],             # MFT-Modified, Last-Access
        0x30: [3],                # Last-Access
    }

    positions = field_map.get(attr_offset, [])
    for i, field_idx in enumerate(positions):
        hex_str = data_hex[i * 16:(i + 1) * 16]
        times[field_idx] = convert_windows_timestamp(hex_str, utc)

    return times

def extract_timestamps_file_name(data_hex: str, attr_offset: int, utc: int):
    times = [None] * 4

    field_map = {
        0x18: [0, 1, 2, 3],  # Created, Modified, MFT-Modified, Last-Access (skip first 8 bytes)
        0x20: [0, 1, 2, 3],  # All 4 timestamps
        0x28: [1, 2, 3],     # Modified, MFT-Modified, Last-Access
        0x30: [2, 3],        # MFT-Modified, Last-Access
        0x38: [3],           # Last-Access
    }

    positions = field_map.get(attr_offset, [])
    start_byte = 8 if attr_offset == 0x18 else 0  # Skip File Reference Address.

    for i, field_idx in enumerate(positions):
        hex_start = (start_byte + i * 8) * 2
        hex_str = data_hex[hex_start:hex_start + 16]
        times[field_idx] = convert_windows_timestamp(hex_str, utc)

    return times

def convert_windows_timestamp(hex_str, utc=0):
    try:
        if isinstance(utc, str):
            utc = int(utc)

        timestamp = struct.unpack("<Q", bytes.fromhex(hex_str))[0]
        if timestamp == 0:
            return None

        utc_time = datetime(1970, 1, 1, tzinfo=timezone.utc) + \
                   timedelta(seconds=(timestamp - 116444736000000000) / 10_000_000)
        target_tz = timezone(timedelta(hours=utc))
        local_time = utc_time.astimezone(target_tz)

        return local_time.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def parse_timestomp(log_record_db_path, utc_offset):
    conn = sqlite3.connect(log_record_db_path)
    try:
        init_timestomp_db(conn)
        rows = fetch_relevant_rows_standard_information(conn)
        process_and_insert(conn, rows, utc_offset, 'STANDARD_INFORMATION')

        # rows = fetch_relevant_rows_file_name(conn)
        # process_and_insert(conn, rows, utc_offset, 'FILE_NAME')
    finally:
        conn.close()
