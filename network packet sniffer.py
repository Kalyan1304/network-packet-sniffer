import socket
import struct

# Protocol numbers
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}

def get_local_ip():
    """Automatically fetches the local IP address of the active network interface."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to an external server to determine local IP
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception as e:
        print(f"Error fetching local IP: {e}")
        return "127.0.0.1"  # Fallback to localhost

def packet_sniffer(filter_protocol=None, filter_port=None):
    """Captures network packets and filters based on protocol and port."""
    try:
        local_ip = get_local_ip()
        print(f"🌍 Local IP Detected: {local_ip}")

        # Create a raw socket
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((local_ip, 0))  # Bind to the detected local IP

        # Include IP headers
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Enable promiscuous mode (Windows only)
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except AttributeError:
            pass  # Not required for Linux

        print("🎯 Sniffing packets... Press Ctrl+C to stop.\n")

        while True:
            raw_data, addr = sniffer.recvfrom(65535)  # Capture a packet
            ip_header = raw_data[:20]  # Extract IP header
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = (version_ihl & 0xF) * 4  # Convert to bytes
            ttl = iph[5]
            protocol = iph[6]
            src_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])

            # Apply protocol filter (if specified)
            if filter_protocol and PROTOCOLS.get(protocol) != filter_protocol:
                continue

            # Parse TCP, UDP, ICMP
            if protocol == 6:  # TCP
                tcp_header = raw_data[ihl:ihl+20]
                tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                src_port, dest_port = tcph[0], tcph[1]

                # Apply port filter (e.g., HTTP packets on port 80)
                if filter_port and (src_port != filter_port and dest_port != filter_port):
                    continue

                print(f"📦 TCP Packet | {src_ip}:{src_port} → {dest_ip}:{dest_port} | TTL: {ttl}")

            elif protocol == 17:  # UDP
                udp_header = raw_data[ihl:ihl+8]
                udph = struct.unpack('!HHHH', udp_header)
                src_port, dest_port = udph[0], udph[1]

                # Apply port filter
                if filter_port and (src_port != filter_port and dest_port != filter_port):
                    continue

                print(f"📦 UDP Packet | {src_ip}:{src_port} → {dest_ip}:{dest_port} | TTL: {ttl}")

            elif protocol == 1:  # ICMP
                icmp_header = raw_data[ihl:ihl+4]
                icmph = struct.unpack('!BBH', icmp_header)
                icmp_type, icmp_code = icmph[0], icmph[1]

                print(f"📦 ICMP Packet | {src_ip} → {dest_ip} | Type: {icmp_type}, Code: {icmp_code}")

    except KeyboardInterrupt:
        print("\n🛑 Stopping packet sniffer.")
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)  # Turn off promiscuous mode
        except AttributeError:
            pass

# Example Usage:
# Capture only HTTP (port 80) TCP packets:
packet_sniffer(filter_protocol="TCP", filter_port=80)
