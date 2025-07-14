# NTFS `$LogFile` *Time‑Stomp* Detector

A lightweight, **pure‑Python** toolkit for forensic examiners who need to spot malicious _time‑stomping_ on NTFS volumes.  
It parses the NTFS transaction journal (`$LogFile`), reconstructs **Undo / Redo** entries for the *STANDARD_INFORMATION* (and optionally *FILE_NAME*) attributes, and flags records whose timestamp roll‑backs betray tampering.

---

## Why Time‑Stomping Matters

Attackers often change file timestamps (“_time‑stomp_”) to frustrate timeline analysis.

NTFS stores **four** distinct timestamps for every file:

| Field | Meaning |
|-------|---------|
| `Created` | First write‑time (birth) |
| `Modified` | Last data change |
| `MFT Modified` | Last metadata change |
| `Accessed` | Last open / read |

Simply altering the resident timestamps in the MFT is easy — but **`$LogFile`** keeps the _true_ history.  
By analysing the journal’s **Undo** (pre‑image) and **Redo** (post‑image) buffers, we can see when an attacker pushed a timestamp **backwards in time**.

---

## How It Works

```
┌──────────────┐    1. Raw 0x00   2. Filtered records      3. ΔT test
│ $LogFile     │──► parse_logfile.py ───────────────────► parse_timestamp.py ──► SQLite table: TimeStomp
└──────────────┘       (creates LogFile.db)                   (adds flags)
```

1. **`parse_logfile.py`**  
   * Scans each **RSTR** & **RCRD** page, reads every *Update / Commit* record and stores it in **`LogFile.db`** (SQLite) with the full Undo / Redo blobs.  
2. **`parse_timestamp.py`**  
   * Extracts the four FILETIME values from each blob (attribute‑offset aware).  
   * Compares **Undo vs. Redo**; if any field moved _backwards_ the event is marked `is_timestomped = 1`.  
3. **SQLite** output gives you a ready‑made queryable table of suspect operations.

---

## Repository Layout

```
.
├── main.py               # Command‑line front‑end
├── parse_logfile.py      # Journal parsing & SQLite ingestion
├── parse_timestamp.py    # Timestamp extraction and ΔT test
├── structure_print.py    # Dataclass definitions & helpers
└── requirements.txt      # (empty – stdlib only)
```

---

## Installation

```bash
# 1. Clone
git clone https://github.com/YongJin04/NTFS-LogFile-Explorer.git
cd ntfs-timestomp-detector

# 2. Create a virtualenv (optional but recommended)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# 3. Install dependencies
# (None – pure stdlib!)
```

Python ≥ 3.8 is recommended.

---

## Quick‑Start

1. **Acquire** the raw **`$LogFile`** from the suspect volume (e.g., `fls` + `icat` or FTK Imager).  
2. **Run the tool**:

```bash
python main.py -f LogFile.raw -t 9
#            │                   └ UTC+9 (Asia/Seoul) – adjust as needed
#            └ path to raw $LogFile
```

The script creates **`log_records.db`** and adds a second table **`TimeStomp`** that contains the detection results.

3. **Investigate**:

```sql
SELECT *
FROM   TimeStomp
WHERE  is_timestomped = 1
ORDER BY redo_create_time DESC;
```

---

## CLI Reference

| Flag | Description |
|------|-------------|
| `-f, --logfile <path>` | Raw **`$LogFile`** to analyse |
| `-t, --utc <offset>`   | Examiner’s **target time‑zone offset** (integer hours, e.g. `0`, `9`, `-5`) – affects human‑readable output |

---

## Detection Logic (Technical Notes)

| Attribute | Offsets handled | Special handling |
|-----------|-----------------|------------------|
| `STANDARD_INFORMATION` | `0x18 0x20 0x28 0x30` | Straight 4 × FILETIME extraction per field map |
| `FILE_NAME` *(optional)* | `0x18 0x20 0x28 0x30 0x38` | Skips first 8 bytes when `attr_offset == 0x18` |

For each timestamp pair `(undo, redo)` the tool tests:

```
undo and redo and undo > redo  →  Time‑stomp
```

All FILETIMEs are converted:

```
FILETIME → Unix epoch (UTC) → target TZ offset (-t)
```

Returned as `YYYY‑MM‑DD HH:MM:SS`.

---

## Output Schema

```sql
CREATE TABLE TimeStomp (
    this_lsn              INTEGER,   -- Journal record pointer
    undo_create_time      TEXT,
    undo_modified_time    TEXT,
    undo_mft_modified_time TEXT,
    undo_last_access_time TEXT,
    redo_create_time      TEXT,
    redo_modified_time    TEXT,
    redo_mft_modified_time TEXT,
    redo_last_access_time TEXT,
    is_timestomped        BOOLEAN,   -- 1 = suspicious
    attr_name             TEXT,      -- STANDARD_INFORMATION / FILE_NAME
    target_vcn            INTEGER,
    cluster_number        INTEGER,
    record_offset         INTEGER,
    attr_offset           INTEGER
);
```

## Extending the Tool

* Enable *FILE_NAME* checks – uncomment two lines in **`parse_timestamp.py`**.  
* Add support for other NTFS attributes by:  
  1. Duplicating `extract_timestamps_*` with the correct field map.  
  2. Writing a matching `fetch_relevant_rows_*` SQL where‑clause.

---
