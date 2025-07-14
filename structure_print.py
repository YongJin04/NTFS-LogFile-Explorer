from dataclasses import dataclass

PAGE_SIZE = 0x1000
RECORD_HEADER_SIZE = 0x30

RSTR_HEADER_STRUCTURE = '<4sHHQIIHHH18sQHHI'  # 4sHHQ IIHHH 18s QHHI 0x40
RCRD_HEADER_STRUCTURE = '<4sHHQIHHHHIQ'  # 4sHHQ IHHHHI Q (Size = 0x28)
RECORD_HEADER_STRUCTURE = '<QQQIIIIH6sHHHHHHHHHHHHQQ'  # QQ QII IIH6s HHHHHHHH HHHHQ Q (Size = 0x58)

@dataclass
class RSTRHeader:
    magic_number: bytes
    update_sequence_offset: int
    update_sequence_count: int
    check_disk_lsn: int
    system_page_size: int
    log_page_size: int
    restart_offset: int
    minor_version: int
    major_version: int
    update_sequence_array: bytes
    current_lsn: int
    log_client_offset: int
    client_list_offset: int
    flags: int

def print_rstr_header(rstr_header):
    print("\n[*] RSTR Header Info")
    print(f"Magic Number         : {rstr_header.magic_number.decode()}")
    print(f"Update Seq Offset    : 0x{rstr_header.update_sequence_offset:04X}")
    print(f"Update Seq Count     : 0x{rstr_header.update_sequence_count:04X}")
    print(f"Check Disk LSN       : 0x{rstr_header.check_disk_lsn:016X}")
    print(f"System Page Size     : 0x{rstr_header.system_page_size:08X}")
    print(f"Log Page Size        : 0x{rstr_header.log_page_size:08X}")
    print(f"Restart Offset       : 0x{rstr_header.restart_offset:04X}")
    print(f"Minor Version        : 0x{rstr_header.minor_version:04X}")
    print(f"Major Version        : 0x{rstr_header.major_version:04X}")
    print(f"Current LSN          : 0x{rstr_header.current_lsn:016X}")
    print(f"Log Client Offset    : 0x{rstr_header.log_client_offset:04X}")
    print(f"Client List Offset   : 0x{rstr_header.client_list_offset:04X}")
    print(f"Flags                : 0x{rstr_header.flags:08X}")

@dataclass
class RCRDHeader:
    magic_number: bytes
    update_sequence_offset: int
    update_sequence_count: int
    last_lsn: int
    flags: int
    page_count: int
    page_position: int
    next_record_offset: int
    word_align: int
    dword_align: int
    last_end_lsn: int


def print_rcrd_header(rcrd_header):
    print("\n[*] RCRD Header Info")
    print(f"Magic Number         : {rcrd_header.magic_number.decode(errors='replace')}")
    print(f"Update Seq Offset    : 0x{rcrd_header.update_sequence_offset:04X}")
    print(f"Update Seq Count     : 0x{rcrd_header.update_sequence_count:04X}")
    print(f"Last LSN/Offset      : 0x{rcrd_header.last_lsn:016X}")
    print(f"Flags                : 0x{rcrd_header.flags:08X}")
    print(f"Page Count           : 0x{rcrd_header.page_count:04X}")
    print(f"Page Position        : 0x{rcrd_header.page_position:04X}")
    print(f"Next Record Offset   : 0x{rcrd_header.next_record_offset:04X}")
    print(f"Word Align           : 0x{rcrd_header.word_align:04X}")
    print(f"DWord Align          : 0x{rcrd_header.dword_align:08X}")
    print(f"Last End LSN         : 0x{rcrd_header.last_end_lsn:016X}")
    
@dataclass
class LogRecordHeader:
    this_lsn: int
    previous_lsn: int
    client_undo_lsn: int
    client_data_length: int
    client_id: int
    record_type: int
    transaction_id: int
    flags: int
    alignment_or_reserved1: bytes
    redo_op: int
    undo_op: int
    redo_offset: int
    redo_length: int
    undo_offset: int
    undo_length: int
    target_attribute: int
    lcn_to_follow: int
    record_offset: int
    attr_offset: int
    cluster_number: int
    page_size: int
    target_vcn: int
    target_lcn: int

def print_log_record_header(header):
    print("\n[*] Log Record Header Info")
    print(f"This LSN             : 0x{header.this_lsn:016X}")
    print(f"Previous LSN         : 0x{header.previous_lsn:016X}")
    print(f"Client Undo LSN      : 0x{header.client_undo_lsn:016X}")
    print(f"Client Data Length   : 0x{header.client_data_length:08X}")
    print(f"Client ID            : 0x{header.client_id:08X}")
    print(f"Record Type          : 0x{header.record_type:08X}")
    print(f"Transaction ID       : 0x{header.transaction_id:08X}")
    print(f"Flags                : 0x{header.flags:04X}")
    print(f"Alignment/Reserved 1 : {header.alignment_or_reserved1.hex()}")
    print(f"Redo OP              : 0x{header.redo_op:04X}")
    print(f"Undo OP              : 0x{header.undo_op:04X}")
    print(f"Redo Offset          : 0x{header.redo_offset:04X}")
    print(f"Redo Length          : 0x{header.redo_length:04X}")
    print(f"Undo Offset          : 0x{header.undo_offset:04X}")
    print(f"Undo Length          : 0x{header.undo_length:04X}")
    print(f"Target Attribute     : 0x{header.target_attribute:04X}")
    print(f"LCNs To Follow       : 0x{header.lcn_to_follow:04X}")
    print(f"Record Offset        : 0x{header.record_offset:04X}")
    print(f"Attr Offset          : 0x{header.attr_offset:04X}")
    print(f"Cluser Number        : 0x{header.cluster_number:04X}")
    print(f"Page Size            : 0x{header.page_size:04X}")
    print(f"Target VCN           : 0x{header.target_vcn:016X}")
    print(f"Target LCN           : 0x{header.target_lcn:016X}")

OPCODE_MAP = {
    0x00: "Noop",
    0x01: "Compensation Log Record",
    0x02: "Initialize File Record Segment",
    0x03: "Deallocate File Record Segment",
    0x04: "Write End Of File Record Segment",
    0x05: "Create Attribute",
    0x06: "Delete Attribute",
    0x07: "Update Resident Value",
    0x08: "Update Non Resident Value",
    0x09: "Update Mapping Pairs",
    0x0A: "Delete Dirty Clusters",
    0x0B: "Set New Attribute Size",
    0x0C: "Add Index Entry Root",
    0x0D: "Delete Index Entry Root",
    0x0E: "Add Index Entry Allocation",
    0x0F: "Delete Index Entry Allocation",
    0x12: "Set Index Entry Ven Allocation",
    0x13: "Update File Name Root",
    0x14: "Update File Name Allocation",
    0x15: "Set Bits In Non Resident Bitmap",
    0x16: "Clear Bits In Non Resident Bitmap",
    0x19: "Prepare Transaction",
    0x1A: "Commit Transaction",
    0x1B: "Forget Transaction",
    0x1C: "Open Non Resident Attribute",
    0x1D: "Open Attribute Table Dump",
    0x1F: "Dirty Page Table Dump",
    0x20: "Transaction Table Dump",
    0x21: "Update Record Data Root",
}
