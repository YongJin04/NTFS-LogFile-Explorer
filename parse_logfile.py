import argparse
import sqlite3
import struct
import sys
import os

from structure_print import (
    read_struct,
    RSTR_HEADER_STRUCTURE, RSTRHeader, print_rstr_header,
    RCRD_HEADER_STRUCTURE, RCRDHeader, print_rcrd_header,
    RECORD_HEADER_STRUCTURE, LogRecordHeader, print_log_record_header,
    OPCODE_MAP,
    PAGE_SIZE,
    RECORD_HEADER_SIZE
)

def read_rstr_header(logfile, base_page_number):
    logfile.seek(base_page_number * PAGE_SIZE)

    rstr_header = read_struct(logfile, RSTR_HEADER_STRUCTURE, RSTRHeader)

    if rstr_header.magic_number.rstrip(b'\x00') != b'RSTR':
        sys.exit("Invalid RSTR magic number. Not a valid Restart Page.")
    
    return rstr_header

def search_current_lsn(logfile, base_page_number, current_lsn):
    logfile.seek(base_page_number * PAGE_SIZE)

    logfile_data = logfile.read()
    searched_current_lsn = find_hex(logfile_data, current_lsn, 8)

    return searched_current_lsn

def read_rcrd_header(logfile, base_page_number):
    logfile.seek(base_page_number * PAGE_SIZE)

    rcrd_header = read_struct(logfile, RCRD_HEADER_STRUCTURE, RCRDHeader)

    if rcrd_header.magic_number.rstrip(b'\x00') != b'RCRD':
        sys.exit("Invalid RCRD magic number. Not a valid Restart Page.")
    
    return rcrd_header

def read_record(logfile, base_page_number, insert_buffer, conn):
    logfile.seek(base_page_number * PAGE_SIZE)
    rcrd_header = read_rcrd_header(logfile, base_page_number)

    logfile.seek(base_page_number * PAGE_SIZE)
    logfile_data = logfile.read(rcrd_header.next_record_offset)

    record_types = [1, 2]  # 0x01 : Update Record, Commit Record / 0x02 : Checkpoint Record
    searched_records = find_hex(logfile_data, record_types, 2)

    searched_records = [x - 0x20 for x in searched_records if x >= 0x30]  # Skip RCTD header. & Move to start address of Record.

    for searched_record in searched_records:
        record_offset = (base_page_number * PAGE_SIZE) + searched_record
        record_header = read_record_header(record_offset, logfile)

        if (record_header.alignment_or_reserved1 == b'\x00' * len(record_header.alignment_or_reserved1) and  # Condition filter to become a record.
            record_header.redo_offset == 0x28 and
            0x00 <= record_header.redo_op <= 0x21 and
            0x00 <= record_header.undo_op <= 0x21 and
            record_header.cluster_number in (0x00, 0x02, 0x04, 0x06) and
            record_header.page_size == 0x02 and
            record_header.redo_length != 0x00 and 
            record_header.redo_length != 0x00):

            redo_offset = record_offset + record_header.redo_offset + RECORD_HEADER_SIZE  # Skip Record Header.
            undo_offset =  record_offset + record_header.undo_offset + RECORD_HEADER_SIZE  # Skip Record Header.
            if ((redo_offset % PAGE_SIZE) + record_header.redo_length <= rcrd_header.next_record_offset and  # Check if rodo and undo data exceeds the page.
                (redo_offset % PAGE_SIZE) + record_header.redo_length <= rcrd_header.next_record_offset):
                logfile.seek(redo_offset)
                redo_data = logfile.read(record_header.redo_length)

                logfile.seek(undo_offset)
                undo_data = logfile.read(record_header.undo_length)

                insert_log_record(conn, record_header, redo_data, undo_data, insert_buffer)

    return

def read_record_header(record_offset, logfile):
    logfile.seek(record_offset)

    record_header = read_struct(logfile, RECORD_HEADER_STRUCTURE, LogRecordHeader)
    
    return record_header

def find_hex(logfile_data, search_hexs, byte_size):
    if not isinstance(search_hexs, list):
        search_hexs = [search_hexs]

    compiled_patterns = []
    for pattern in search_hexs:
        if isinstance(pattern, int):
            compiled_patterns.append(pattern.to_bytes(byte_size, byteorder='little'))
        elif isinstance(pattern, bytes):
            if len(pattern) != byte_size:
                raise ValueError(f"Byte pattern must be exactly {byte_size} bytes long.")
            compiled_patterns.append(pattern)
        else:
            raise TypeError("Patterns must be int or bytes.")

    matched_offsets = []
    offset = 0
    data_len = len(logfile_data)

    while offset + byte_size <= data_len:
        segment = logfile_data[offset:offset + byte_size]
        if segment in compiled_patterns:
            matched_offsets.append(offset)
        offset += 8

    return sorted(matched_offsets)

def init_db(db_path="log_records.db"):
    db_path = os.path.abspath(db_path)
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE LogFile (
            this_lsn INTEGER,
            previous_lsn INTEGER,
            record_type INTEGER,
            redo_op_value INTEGER,
            redo_op_name TEXT,
            redo_data TEXT,
            redo_data_length INTEGER,
            undo_op_value INTEGER,
            undo_op_name TEXT,
            undo_data TEXT,
            undo_data_length INTEGER,
            target_vcn INTEGER,
            target_lcn INTEGER,
            cluster_number INTEGER,
            record_offset INTEGER,
            attr_offset INTEGER
        )
    ''')
    conn.commit()
    return conn, db_path

def insert_log_record(conn, record_header, redo_data: bytes, undo_data: bytes, insert_buffer):
    insert_buffer.append((
        f"0x{record_header.this_lsn:X}",
        f"0x{record_header.previous_lsn:X}",
        f"0x{record_header.record_type:X}",
        f"0x{record_header.redo_op:X}",
        OPCODE_MAP.get(record_header.redo_op, "UNKNOWN"),
        redo_data.hex(),
        f"0x{record_header.redo_length:X}",
        f"0x{record_header.undo_op:X}",
        OPCODE_MAP.get(record_header.undo_op, "UNKNOWN"),
        undo_data.hex(),
        f"0x{record_header.undo_length:X}",
        f"0x{record_header.target_vcn:X}",
        f"0x{record_header.target_lcn:X}",
        f"0x{record_header.cluster_number:X}",
        f"0x{record_header.record_offset:X}",
        f"0x{record_header.attr_offset:X}"
    ))

def flush_insert_buffer(conn, insert_buffer):
    if not insert_buffer:
        return

    cursor = conn.cursor()
    cursor.executemany('''
        INSERT INTO LogFile (
            this_lsn, previous_lsn, record_type,
            redo_op_value, redo_op_name, redo_data, redo_data_length,
            undo_op_value, undo_op_name, undo_data, undo_data_length,
            target_vcn, target_lcn, cluster_number,
            record_offset, attr_offset
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', insert_buffer)
    conn.commit()
    insert_buffer.clear()

def parse_logfile(logfile, logfile_path):
    conn, log_record_db_path = init_db()
    insert_buffer = []
    base_page_number = 0
    file_size = os.path.getsize(logfile_path)

    rstr_header = read_rstr_header(logfile, base_page_number)

    base_page_number = base_page_number + 4  # Skip RSTR, Buffer page.
    searched_current_lsn = search_current_lsn(logfile, base_page_number, rstr_header.current_lsn)

    for current_lsn_offset in searched_current_lsn:
        base_page_number = current_lsn_offset // PAGE_SIZE
        while True:
            if file_size // PAGE_SIZE <= base_page_number:
                base_page_number = 4  # Wrap around

            read_record(logfile, base_page_number, insert_buffer, conn)
            base_page_number = base_page_number + 1

            if base_page_number == current_lsn_offset // PAGE_SIZE:
                break
        break  # 현재는 하나의 current_lsn만 처리

    flush_insert_buffer(conn, insert_buffer)
    conn.close()
    return log_record_db_path
