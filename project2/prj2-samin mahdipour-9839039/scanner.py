import argparse
import socket
import os
import struct


def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner CLI Tool")

    # IP Scan Command
    ip_scan_parser = parser.add_argument_group("IP Scan Options\n")
    ip_scan_parser.add_argument("--ipscan", action="store_true", help="Perform IP scanning")
    ip_scan_parser.add_argument("-m", "--subnet-mask", type=int, help="Subnet mask (e.g., 24)")
    ip_scan_parser.add_argument("start_ip", help="Start IP address")
    ip_scan_parser.add_argument("end_ip", help="End IP address", nargs="?")  # Make end_ip optional for portscan

    # Port Scan Command
    port_scan_parser = parser.add_argument_group("Port Scan Options")
    port_scan_parser.add_argument("--portscan", action="store_true", help="Perform port scanning")
    port_scan_parser.add_argument("--tcp", action="store_true", help="Use TCP protocol")
    port_scan_parser.add_argument("--udp", action="store_true", help="Use UDP protocol")
    port_scan_parser.add_argument("target_ip", nargs="?", default=None, help="Target IP address for port scanning")
    port_scan_parser.add_argument("start_port", type=int, nargs="?", default=None, help="Start port for scanning")
    port_scan_parser.add_argument("end_port", type=int, nargs="?", default=None, help="End port for scanning")

    args = parser.parse_args()

    # Check for invalid combination of arguments
    if args.ipscan and args.portscan:
        parser.error("Invalid combination of arguments. Use either IP scan or port scan.")
    # If it's a port scan, set default values for start_ip and end_ip
    if args.portscan:
        args.end_port = int(args.target_ip)
        args.target_ip = str(args.start_ip)
        args.start_ip = None
        args.start_port = int(args.end_ip)
        args.end_ip = None

    return args





def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def int_to_ip(ip_int):
    return socket.inet_ntoa(struct.pack("!I", ip_int))

def ip_scan(start_ip, end_ip, subnet_mask):
    active_machines = []

    start_int = ip_to_int(start_ip)

    # If end_ip is provided, scan the IP range; otherwise, scan only the specified IP
    if end_ip:
        end_int = ip_to_int(end_ip)
        subnet_int = 2 ** (32 - subnet_mask)

        for i in range(subnet_int):
            current_ip_int = start_int + i
            current_ip = int_to_ip(current_ip_int)

            # Perform socket connection to check if the IP is reachable
            try:
                socket.create_connection((current_ip, 80), timeout=1)
                active_machines.append(current_ip)
            except (socket.timeout, socket.error):
                pass
    else:
        try:
            socket.create_connection((start_ip, 80), timeout=1)
            active_machines.append(start_ip)
        except (socket.timeout, socket.error):
            pass

    return active_machines

def tcp_port_scan(target_ip, port):
    try:
        socket.create_connection((target_ip, port), timeout=0.5)
        print(f"Port {port} (TCP) is open")
        return True
    except (socket.timeout, socket.error):
        print(f"Port {port} (TCP) is closed")
        return False

def udp_port_scan(target_ip, port):
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.settimeout(0.5)
        udp_socket.sendto(b'', (target_ip, port))
        udp_socket.close()  # Close the UDP socket after sending the packet
        print(f"Port {port} (UDP) is open")
        return True
    except (socket.timeout, socket.error):
        print(f"Port {port} (UDP) is closed")
        return False



def port_scan(target_ip, start_port, end_port, tcp_scan=True, udp_scan=True):
    open_ports = []
    print('PORT SCANNING')

    # Check if both start_port and end_port are provided
    if start_port is not None and end_port is not None:
        for port in range(start_port, end_port + 1):
            if tcp_scan and tcp_port_scan(target_ip, port):
                open_ports.append((port, "TCP"))
            elif udp_scan and udp_port_scan(target_ip, port):
                open_ports.append((port, "UDP"))
    else:
        print("Please provide both start_port and end_port for port scanning.")
        return open_ports  # Return an empty list to avoid further processing

    return open_ports



def identify_services(target_ip, open_ports):
    services = []

    for port, protocol in open_ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                s.connect((target_ip, port))
                service_info = s.recv(1024).decode('utf-8')
                services.append((port, protocol, service_info))
        except (socket.timeout, socket.error):
            pass

    return services

def display_and_save_report(active_machines, open_ports, services):
    print("\n=== Network Scan Report ===")

    # Display active machines
    print("\nActive Machines:")
    for machine in active_machines:
        print(f"- {machine}")

    # Display open ports
    print("\nOpen Ports:")
    for port, protocol in open_ports:
        print(f"- Port {port} ({protocol}) is open")

    # Display identified services
    print("\nIdentified Services:")
    for port, protocol, service_info in services:
        print(f"- Port {port} ({protocol}): {service_info}")

    # Save the report to a text file
    with open("NetworkScanReport.txt", "w") as report_file:
        report_file.write("=== Network Scan Report ===\n\n")

        # Write active machines
        report_file.write("\nActive Machines:\n")
        for machine in active_machines:
            report_file.write(f"- {machine}\n")

        # Write open ports
        report_file.write("\nOpen Ports:\n")
        for port, protocol in open_ports:
            report_file.write(f"- Port {port} ({protocol}) is open\n")

        # Write identified services
        report_file.write("\nIdentified Services:\n")
        for port, protocol, service_info in services:
            report_file.write(f"- Port {port} ({protocol}): {service_info}\n")

    print("\nReport saved to NetworkScanReport.txt")

def main():
    args = parse_arguments()

    if args.ipscan:
        print('IP SCANNING MODE')
        active_machines = ip_scan(args.start_ip, args.end_ip, args.subnet_mask)
        display_and_save_report(active_machines, [], [])
    elif args.portscan:
        print('PORT SCANNING MODE')
        open_ports = port_scan(args.target_ip, args.start_port, args.end_port, args.tcp, args.udp)
        display_and_save_report([], open_ports, [])



if __name__ == "__main__":
    main()
