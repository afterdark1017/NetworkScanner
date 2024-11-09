# main_cli.py
import argparse
from network_mapping import detect_os, detect_services
from database import setup_database, insert_scan_result, fetch_all_scans

def main():
    parser = argparse.ArgumentParser(description='Network Scanner')
    parser.add_argument('--ip', type=str, help='IP address to scan')
    args = parser.parse_args()

    if args.ip:
        print(f"Scanning IP: {args.ip}")
        try:
            os_info = detect_os(args.ip)
            print(f"OS Info: {os_info}")
            service_info = detect_services(args.ip, range(20, 85))  # Scanning common ports
            print(f"Service Info: {service_info}")
            # Example: Inserting a dummy vulnerability check
            insert_scan_result(args.ip, 80, 'HTTP', 'Unknown', 'None', os_info)
        except Exception as e:
            print(f"An error occurred: {e}")

if __name__ == "__main__":
    setup_database()
    main()