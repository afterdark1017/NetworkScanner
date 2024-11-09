from scapy.all import IP, TCP, sr1
import threading
import logging
from prettytable import PrettyTable
import ipaddress

logging.basicConfig(level=logging.INFO, format='%(message)s')

def scan_port(ip, port):
    try:
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK indicates open port
                return True
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK indicates closed port
                return False
    except Exception as e:
        logging.error(f"Error scanning port {port} on {ip}: {e}")
    return False  # No response or other issues are treated as closed

def detect_os(ip):
    packet = IP(dst=ip)/TCP(dport=80, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        if response.ttl <= 64:
            logging.info(f"Host {ip} is up. Detected OS: Linux/Unix")
            return "Linux/Unix"
        elif response.ttl <= 128:
            logging.info(f"Host {ip} is up. Detected OS: Windows")
            return "Windows"
    else:
        logging.warning(f"Host {ip} seems to be down.")
    return "Unknown"

def detect_services(ip, ports=None):
    if ports is None:
        ports = range(0, 1001)  # Default range from 0 to 1000
    open_ports = {}
    lock = threading.Lock()

    def scan_and_update(port):
        if scan_port(ip, port):
            with lock:
                open_ports[port] = 'Open'
        else:
            with lock:
                open_ports[port] = 'Closed'

    threads = [threading.Thread(target=scan_and_update, args=(port,)) for port in ports]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    return open_ports

def format_service_info(service_info):
    table = PrettyTable()
    table.field_names = ["Port", "Status"]
    for port, status in sorted(service_info.items()):
        table.add_row([port, status])
    return table

def scan_network(ip_range):
    try:
        network = ipaddress.ip_network(ip_range, strict=False)
        for ip in network:
            ip_str = str(ip)
            os_info = detect_os(ip_str)
            if os_info != "Unknown":
                print(f"Host {ip_str} is up. Detected OS: {os_info}")
                service_info = detect_services(ip_str)
                print("Service Info:")
                print(format_service_info(service_info))
    except ValueError as e:
        logging.error(f"Invalid IP range: {e}")

if __name__ == "__main__":
    ip_range = input("Enter IP address or range (e.g., 192.168.1.0/24): ")
    scan_network(ip_range)