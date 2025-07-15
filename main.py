import argparse
from parse_logfile import parse_logfile
from parse_timestamp import parse_timestomp
from parse_mft import parse_mft
import os

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--logfile", required=True, help="Enter $LogFile File.")
    parser.add_argument("-t", "--utc", required=True, help="Enter UTC Time.")
    parser.add_argument("-m", "--mft", required=False, help="Enter $MFT File (optional).")
    args = parser.parse_args()

    with open(args.logfile, 'rb') as logfile:
        log_record_db_path = parse_logfile(logfile, args.logfile)
        print("[+] LogFile parsing completed successfully.")

        parse_timestomp(log_record_db_path, args.utc)
        print("[+] Timestamp analysis completed successfully.")

        if args.mft and os.path.exists(args.mft):
            with open(args.mft, 'rb') as mftfile:
                parse_mft(mftfile, args.mft, args.utc, log_record_db_path)
                print("[+] MFT parsing completed successfully.")
