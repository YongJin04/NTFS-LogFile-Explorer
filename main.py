import argparse
from parse_logfile import parse_logfile
from parse_timestamp import parse_timestomp

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--logfile", required=True, help="Enter $LogFile File.")
    parser.add_argument("-t", "--utc", required=True, help="Enter UTC Time.")
    args = parser.parse_args()

    with open(args.logfile, 'rb') as logfile:
        log_record_db_path = parse_logfile(logfile, args.logfile)
        parse_timestomp(log_record_db_path, args.utc)
