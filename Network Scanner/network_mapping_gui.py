from scapy.all import IP, TCP, UDP, sr1, sr, ICMP
import threading
import logging
from prettytable import PrettyTable
import ipaddress
import tkinter as tk

logging.basicConfig(level=logging.INFO, format='%(message)s')

def scan_port(ip, port, scan_type, output_area=None):
    try:
        if scan_type == '-sS':  # SYN Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-sT':  # Connect Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-sU':  # UDP Scan
            packet = IP(dst=ip)/UDP(dport=port)
        elif scan_type == '-sF':  # FIN Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="F")
        elif scan_type == '-sX':  # Xmas Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="FPU")
        elif scan_type == '-sN':  # Null Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="")
        elif scan_type == '-sA':  # ACK Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="A")
        elif scan_type == '-sW':  # Window Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="A")
        elif scan_type == '-sM':  # Maimon Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="F")
        elif scan_type == '-sI':  # Idle Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-sR':  # RPC Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-sY':  # SCTP INIT Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-sZ':  # SCTP COOKIE ECHO Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-sO':  # IP Protocol Scan
            packet = IP(dst=ip)/ICMP()
        elif scan_type == '-b':  # FTP Bounce Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        elif scan_type == '-Pn':  # No Ping Scan
            packet = IP(dst=ip)/TCP(dport=port, flags="S")
        else:
            if output_area:
                output_area.insert(tk.END, f"Unknown scan type: {scan_type}\n")
            return False

        response = sr1(packet, timeout=2, verbose=0)
        if response and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:  # SYN-ACK indicates open port
                return True
            elif response.getlayer(TCP).flags == 0x14:  # RST-ACK indicates closed port
                return False
        elif response and response.haslayer(UDP):
            return True  # UDP response indicates open port
        else:
            return True  # Assume open if no response for TCP or UDP
    except Exception as e:
        if output_area:
            output_area.insert(tk.END, f"Error scanning port {port} on {ip}: {e}\n")
    return True  # Assume open if an exception occurs

def detect_os(ip, output_area=None):
    packet = IP(dst=ip)/TCP(dport=80, flags="S")
    response = sr1(packet, timeout=1, verbose=0)
    if response:
        if response.ttl <= 64:
            if output_area:
                output_area.insert(tk.END, f"Host {ip} is up. Detected OS: Linux/Unix\n")
            return "Linux/Unix"
        elif response.ttl <= 128:
            if output_area:
                output_area.insert(tk.END, f"Host {ip} is up. Detected OS: Windows\n")
            return "Windows"
    else:
        if output_area:
            output_area.insert(tk.END, f"Host {ip} seems to be down.\n")
    return "Unknown"

def detect_services(ip, ports=None, scan_type='-sS'):
    if ports is None:
        ports = range(0, 1001)  # Default range from 0 to 1000
    open_ports = {}
    lock = threading.Lock()

    def scan_and_update(port):
        if scan_port(ip, port, scan_type):
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

def scan_network(ip, scan_type='-sS', output_area=None):
    try:
        if output_area:
            output_area.insert(tk.END, f"Scanning IP: {ip}\n")
        os_info = detect_os(ip, output_area)
        if os_info != "Unknown":
            if output_area:
                output_area.insert(tk.END, f"Host {ip} is up. Detected OS: {os_info}\n")
            service_info = detect_services(ip, scan_type=scan_type)
            if output_area:
                output_area.insert(tk.END, "Service Info:\n")
                output_area.insert(tk.END, f"{format_service_info(service_info)}\n")
    except ValueError as e:
        if output_area:
            output_area.insert(tk.END, f"Invalid IP address: {e}\n")

if __name__ == "__main__":
    ip = "192.168.1.1"  # Example IP address
    scan_type = '-sS'  # Example scan type
    scan_network(ip, scan_type)
