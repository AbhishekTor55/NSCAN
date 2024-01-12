from termcolor import colored

ascii_art = '''
::::    :::  ::::::::   ::::::::      :::     ::::    :::
:+:+:   :+: :+:    :+: :+:    :+:   :+: :+:   :+:+:   :+:
:+:+:+  +:+ +:+        +:+         +:+   +:+  :+:+:+  +:+
+#+ +:+ +#+ +#++:++#++ +#+        +#++:++#++: +#+ +:+ +#+
+#+  +#+#+#        +#+ +#+        +#+     +#+ +#+  +#+#+#
#+#   #+#+# #+#    #+# #+#    #+# #+#     #+# #+#   #+##+
###    ####  ########   ########  ###     ### ###    ####
'''

colored_ascii_art = colored(ascii_art, 'red', attrs=['bold'])

print(colored_ascii_art)

import argparse
import socket
import threading
from queue import Queue
from getmac import get_mac_address
import xml.etree.ElementTree as ET

# ANSI escape codes for colors
BLUE = '\033[94m'
YELLOW = '\033[93m'
ENDC = '\033[0m'  # Reset color

def get_service_name(port):
    try:
        service_name = socket.getservbyport(port)
        return service_name
    except (socket.error, OSError):
        return "Unknown"

def get_mac(target_ip):
    try:
        mac_address = get_mac_address(ip=target_ip)
        return mac_address
    except Exception as e:
        return str(e)

def scan(target_ip, target_ports, show_mac, file_format, filename, mtu):
    results = {}

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        sock.close()

        if result == 0:
            service_name = get_service_name(port)
            mac_address = get_mac(target_ip) if show_mac else "N/A"
            results[port] = {"status": "open", "service": service_name, "mac_address": mac_address}
        else:
            results[port] = {"status": "closed", "service": "N/A", "mac_address": "N/A"}

        # Increment the processed count
        with processed_count_lock:
            processed_count[0] += 1

        # Print progress percentage
        progress = (processed_count[0] / total_ports) * 100
        print(f"\r{BLUE}Progress: {progress:.2f}% complete{ENDC}", end="", flush=True)

    def worker():
        while True:
            port = port_queue.get()
            if port is None:
                break
            scan_port(port)
            port_queue.task_done()

    processed_count_lock = threading.Lock()
    processed_count = [0]

    port_queue = Queue()

    for _ in range(30):  # Number of worker threads
        thread = threading.Thread(target=worker)
        thread.daemon = True
        thread.start()

    total_ports = len(target_ports)

    for port in target_ports:
        port_queue.put(port)

    port_queue.join()

    print(f"\n{YELLOW}Scan complete.{ENDC}")

    if file_format == "xml":
        save_to_xml(results, filename)
    elif file_format == "txt":
        save_to_txt(results, filename)

    return results

def save_to_xml(results, filename):
    if not filename.endswith(".xml"):  # Check if the extension is already present
        filename += ".xml"

    root = ET.Element("ScanResults")
    for port, data in results.items():
        item = ET.SubElement(root, "Port")
        ET.SubElement(item, "Number").text = str(port)
        ET.SubElement(item, "Status").text = data["status"]
        ET.SubElement(item, "Service").text = data["service"]
        ET.SubElement(item, "MAC_Address").text = data["mac_address"]

    tree = ET.ElementTree(root)
    tree.write(filename)

def save_to_txt(results, filename):
    if not filename.endswith(".txt"):  # Check if the extension is already present
        filename += ".txt"

    with open(filename, "w") as file:
        for port, data in results.items():
            file.write(f"Port {port}: Status: {data['status']}, Service: {data['service']}, MAC Address: {data['mac_address']}\n")

def main():
    parser = argparse.ArgumentParser(description="Make By Linucroothackers.in.")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--ports", help="Port range (e.g., 1-65535)", required=True)
    parser.add_argument("-m", "--show-mac", action="store_true", help="Show MAC addresses")
    parser.add_argument("-f", "--file-format", choices=["xml", "txt"], default="txt", help="Specify the file format for the scan report (xml or txt)")
    parser.add_argument("-o", "--output-filename", default="scan_results", help="Specify the output filename (without extension)")
    parser.add_argument("--mtu", type=int, default=1500, help="Fragment packets with the given MTU")
    args = parser.parse_args()

    target_ip = args.target
    port_range = list(map(int, args.ports.split('-')))
    target_ports = list(range(port_range[0], port_range[1] + 1))

    output_filename = args.output_filename

    if not output_filename.endswith(f".{args.file_format}"):
        output_filename += f".{args.file_format}"

    results = scan(target_ip, target_ports, args.show_mac, args.file_format, output_filename, args.mtu)

    open_ports = [port for port, data in results.items() if data["status"] == "open"]

    if open_ports:
        print(f"\n{YELLOW}Open Ports:{ENDC}")
        for port in open_ports:
            print(f"Port {port} is open, Service: {results[port]['service']}, MAC Address: {results[port]['mac_address']}")
    else:
        print(f"\n{YELLOW}This Port is closed.{ENDC}")

if __name__ == "__main__":
    main()
