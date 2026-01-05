#!/usr/bin/env python3
"""
Network Packet Sniffer
Educational tool for analyzing network traffic and understanding protocols
Requires: scapy library (pip install scapy)
Platform: Kali Linux (or any Linux distribution)
Usage: Run with sudo privileges for raw socket access
"""

from scapy.all import *
import sys
import argparse
from datetime import datetime
import threading
import time

class NetworkSniffer:
    def __init__(self, interface=None, filter_expr=None, packet_count=0):
        self.interface = interface
        self.filter_expr = filter_expr
        self.packet_count = packet_count
        self.captured_packets = []
        self.stats = {
            'total': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'http': 0,
            'https': 0,
            'dns': 0,
            'other': 0
        }
    
    def packet_handler(self, packet):
        """Process each captured packet"""
        self.stats['total'] += 1
        self.captured_packets.append(packet)
        
        # Get timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Extract basic packet information
        packet_info = self.analyze_packet(packet)
        
        # Update statistics
        self.update_stats(packet)
        
        # Display packet information
        self.display_packet_info(timestamp, packet_info, packet)
        
        # Optional: Save interesting packets for detailed analysis
        if len(self.captured_packets) % 50 == 0:
            print(f"\n[INFO] Captured {len(self.captured_packets)} packets so far...")
            self.display_stats()
    
    def analyze_packet(self, packet):
        """Analyze packet and extract relevant information"""
        info = {
            'src_ip': 'N/A',
            'dst_ip': 'N/A',
            'protocol': 'Unknown',
            'src_port': 'N/A',
            'dst_port': 'N/A',
            'length': len(packet),
            'payload_preview': ''
        }
        
        # Check if packet has IP layer
        if packet.haslayer(IP):
            info['src_ip'] = packet[IP].src
            info['dst_ip'] = packet[IP].dst
            info['protocol'] = packet[IP].proto
            
            # Check for TCP
            if packet.haslayer(TCP):
                info['protocol'] = 'TCP'
                info['src_port'] = packet[TCP].sport
                info['dst_port'] = packet[TCP].dport
                
                # Check for HTTP/HTTPS
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    info['protocol'] = 'HTTP'
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    info['protocol'] = 'HTTPS'
                
                # Extract payload preview
                if packet.haslayer(Raw):
                    payload = packet[Raw].load
                    info['payload_preview'] = self.safe_decode(payload[:50])
            
            # Check for UDP
            elif packet.haslayer(UDP):
                info['protocol'] = 'UDP'
                info['src_port'] = packet[UDP].sport
                info['dst_port'] = packet[UDP].dport
                
                # Check for DNS
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    info['protocol'] = 'DNS'
                    if packet.haslayer(DNS):
                        if packet[DNS].qr == 0:  # Query
                            info['payload_preview'] = f"DNS Query: {packet[DNS].qd.qname.decode()}"
                        else:  # Response
                            info['payload_preview'] = f"DNS Response"
            
            # Check for ICMP
            elif packet.haslayer(ICMP):
                info['protocol'] = 'ICMP'
                info['payload_preview'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        
        # Check for ARP
        elif packet.haslayer(ARP):
            info['protocol'] = 'ARP'
            info['src_ip'] = packet[ARP].psrc
            info['dst_ip'] = packet[ARP].pdst
            info['payload_preview'] = f"Operation: {packet[ARP].op}"
        
        return info
    
    def safe_decode(self, data):
        """Safely decode bytes to string"""
        try:
            return data.decode('utf-8', errors='ignore').replace('\n', '\\n').replace('\r', '\\r')
        except:
            return str(data)[:50]
    
    def update_stats(self, packet):
        """Update packet statistics"""
        if packet.haslayer(TCP):
            self.stats['tcp'] += 1
            if packet.haslayer(Raw):
                payload = packet[Raw].load
                if b'HTTP' in payload:
                    self.stats['http'] += 1
        elif packet.haslayer(UDP):
            self.stats['udp'] += 1
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                self.stats['dns'] += 1
        elif packet.haslayer(ICMP):
            self.stats['icmp'] += 1
        else:
            self.stats['other'] += 1
    
    def display_packet_info(self, timestamp, info, packet):
        """Display formatted packet information"""
        print(f"\n[{timestamp}] Packet #{self.stats['total']}")
        print(f"  Protocol: {info['protocol']}")
        print(f"  Source: {info['src_ip']}:{info['src_port']}")
        print(f"  Destination: {info['dst_ip']}:{info['dst_port']}")
        print(f"  Length: {info['length']} bytes")
        
        if info['payload_preview']:
            print(f"  Payload Preview: {info['payload_preview']}")
        
        # Show packet layers for educational purposes
        try:
            layers = [layer.__name__ for layer in packet.layers()]
            print(f"  Layers: {' -> '.join(layers)}")
        except:
            print(f"  Layers: {len(packet.layers())} layers detected")
    
    def display_stats(self):
        """Display current statistics"""
        print("\n" + "="*50)
        print("PACKET STATISTICS")
        print("="*50)
        print(f"Total Packets: {self.stats['total']}")
        print(f"TCP: {self.stats['tcp']}")
        print(f"UDP: {self.stats['udp']}")
        print(f"ICMP: {self.stats['icmp']}")
        print(f"HTTP: {self.stats['http']}")
        print(f"DNS: {self.stats['dns']}")
        print(f"Other: {self.stats['other']}")
        print("="*50)
    
    def start_sniffing(self):
        """Start packet capture"""
        print(f"Starting packet capture...")
        print(f"Interface: {self.interface or 'All interfaces'}")
        print(f"Filter: {self.filter_expr or 'None'}")
        print(f"Packet count: {self.packet_count or 'Unlimited'}")
        print("Press Ctrl+C to stop\n")
        
        try:
            sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=self.packet_handler,
                count=self.packet_count,
                store=0  # Don't store packets in memory to save RAM
            )
        except KeyboardInterrupt:
            print("\n\nCapture stopped by user")
            self.display_stats()
            self.save_analysis()
    
    def save_analysis(self):
        """Save captured packets analysis to file"""
        if self.captured_packets:
            filename = f"packet_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("NETWORK PACKET ANALYSIS REPORT\n")
                f.write("="*50 + "\n")
                f.write(f"Capture Date: {datetime.now()}\n")
                f.write(f"Total Packets: {len(self.captured_packets)}\n\n")
                
                # Write detailed analysis of first 10 packets
                f.write("DETAILED PACKET ANALYSIS (First 10 packets):\n")
                f.write("-"*50 + "\n")
                
                for i, packet in enumerate(self.captured_packets[:10]):
                    f.write(f"\nPacket #{i+1}:\n")
                    f.write(packet.show(dump=True))
                    f.write("\n" + "-"*30 + "\n")
            
            print(f"\nDetailed analysis saved to: {filename}")

def get_interfaces():
    """Get available network interfaces"""
    interfaces = get_if_list()
    print("Available network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  {i}: {iface}")
    return interfaces

def main():
    parser = argparse.ArgumentParser(description="Educational Network Packet Sniffer")
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-f", "--filter", help="BPF filter expression")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("--list-interfaces", action="store_true", help="List available interfaces")
    
    args = parser.parse_args()
    
    # Check if running as root
    if os.geteuid() != 0:
        print("Warning: This script requires root privileges for raw socket access")
        print("Please run with: sudo python3 network_sniffer.py")
        sys.exit(1)
    
    if args.list_interfaces:
        get_interfaces()
        return
    
    # Create sniffer instance
    sniffer = NetworkSniffer(
        interface=args.interface,
        filter_expr=args.filter,
        packet_count=args.count
    )
    
    # Display available interfaces if none specified
    if not args.interface:
        print("No interface specified. Available interfaces:")
        get_interfaces()
        print("\nUsing all interfaces for capture...")
    
    # Start packet capture
    sniffer.start_sniffing()

if __name__ == "__main__":
    import os
    main()
