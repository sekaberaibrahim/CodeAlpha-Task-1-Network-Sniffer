#!/usr/bin/env python3
"""
Advanced Network Traffic Analyzer
Developed by: Sekabera Ibrahim
Purpose: Comprehensive network packet interception and protocol analysis
Requirements: scapy library (pip install scapy)
Execution Environment: Kali Linux (Linux-based systems)
Execution Method: sudo python3 network_traffic_analyzer.py
"""

from scapy.all import *
import sys
import argparse
from datetime import datetime
import threading
import time
from collections import defaultdict

class TrafficAnalyzer:
    def __init__(self, network_interface=None, packet_filter=None, max_packets=0):
        self.network_interface = network_interface
        self.packet_filter = packet_filter
        self.max_packets = max_packets
        self.packet_collection = []
        self.traffic_metrics = {
            'packet_total': 0,
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'http_traffic': 0,
            'https_traffic': 0,
            'dns_queries': 0,
            'other_protocols': 0,
            'arp_packets': 0,
            'dhcp_packets': 0
        }
        self.protocol_breakdown = defaultdict(int)
        self.source_destinations = defaultdict(int)
    
    def process_packet(self, packet):
        """Intercept and process each network packet"""
        self.traffic_metrics['packet_total'] += 1
        self.packet_collection.append(packet)
        
        # Current time capture
        time_capture = datetime.now().strftime("%H:%M:%S")
        
        # Execute packet analysis
        packet_data = self.dissect_packet(packet)
        
        # Refresh metrics
        self.refresh_metrics(packet)
        
        # Output formatted packet details
        self.print_packet_details(time_capture, packet_data, packet)
        
        # Periodic status updates
        if len(self.packet_collection) % 50 == 0:
            print(f"\n[STATUS] Total packets intercepted: {len(self.packet_collection)}")
            self.print_metrics()
    
    def dissect_packet(self, packet):
        """Dissect packet and extract protocol-specific information"""
        extracted_data = {
            'source_address': 'N/A',
            'dest_address': 'N/A',
            'protocol_type': 'Unknown',
            'source_port': 'N/A',
            'dest_port': 'N/A',
            'packet_size': len(packet),
            'data_preview': ''
        }
        
        # IP Layer Analysis
        if packet.haslayer(IP):
            extracted_data['source_address'] = packet[IP].src
            extracted_data['dest_address'] = packet[IP].dst
            extracted_data['protocol_type'] = packet[IP].proto
            
            # TCP Protocol Branch
            if packet.haslayer(TCP):
                extracted_data['protocol_type'] = 'TCP'
                extracted_data['source_port'] = packet[TCP].sport
                extracted_data['dest_port'] = packet[TCP].dport
                
                # Application Layer Detection
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    extracted_data['protocol_type'] = 'HTTP'
                elif packet[TCP].dport == 443 or packet[TCP].sport == 443:
                    extracted_data['protocol_type'] = 'HTTPS'
                elif packet[TCP].dport == 22 or packet[TCP].sport == 22:
                    extracted_data['protocol_type'] = 'SSH'
                
                # Payload Extraction
                if packet.haslayer(Raw):
                    raw_payload = packet[Raw].load
                    extracted_data['data_preview'] = self.decode_safely(raw_payload[:50])
            
            # UDP Protocol Branch
            elif packet.haslayer(UDP):
                extracted_data['protocol_type'] = 'UDP'
                extracted_data['source_port'] = packet[UDP].sport
                extracted_data['dest_port'] = packet[UDP].dport
                
                # Service Identification
                if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                    extracted_data['protocol_type'] = 'DNS'
                    if packet.haslayer(DNS):
                        if packet[DNS].qr == 0:
                            domain = packet[DNS].qd.qname.decode()
                            extracted_data['data_preview'] = f"DNS Query: {domain}"
                        else:
                            extracted_data['data_preview'] = f"DNS Response"
                elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                    extracted_data['protocol_type'] = 'DHCP'
            
            # ICMP Protocol Branch
            elif packet.haslayer(ICMP):
                extracted_data['protocol_type'] = 'ICMP'
                extracted_data['data_preview'] = f"Type: {packet[ICMP].type}, Code: {packet[ICMP].code}"
        
        # ARP Protocol Analysis
        elif packet.haslayer(ARP):
            extracted_data['protocol_type'] = 'ARP'
            extracted_data['source_address'] = packet[ARP].psrc
            extracted_data['dest_address'] = packet[ARP].pdst
            operation_types = {1: "Request", 2: "Reply"}
            op_type = operation_types.get(packet[ARP].op, "Unknown")
            extracted_data['data_preview'] = f"ARP {op_type}"
        
        return extracted_data
    
    def decode_safely(self, byte_data):
        """Secure byte-to-string conversion"""
        try:
            decoded_string = byte_data.decode('utf-8', errors='ignore')
            decoded_string = decoded_string.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            return decoded_string[:50]
        except Exception as e:
            return f"[Decode Error: {str(e)[:20]}]"
    
    def refresh_metrics(self, packet):
        """Update protocol-level statistics"""
        # TCP Analysis
        if packet.haslayer(TCP):
            self.traffic_metrics['tcp_count'] += 1
            self.protocol_breakdown['TCP'] += 1
            
            if packet.haslayer(Raw):
                payload_content = packet[Raw].load
                if b'HTTP' in payload_content or b'GET' in payload_content:
                    self.traffic_metrics['http_traffic'] += 1
                    self.protocol_breakdown['HTTP'] += 1
        
        # UDP Analysis
        elif packet.haslayer(UDP):
            self.traffic_metrics['udp_count'] += 1
            self.protocol_breakdown['UDP'] += 1
            
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                self.traffic_metrics['dns_queries'] += 1
                self.protocol_breakdown['DNS'] += 1
            elif packet[UDP].dport == 67 or packet[UDP].dport == 68:
                self.traffic_metrics['dhcp_packets'] += 1
                self.protocol_breakdown['DHCP'] += 1
        
        # ICMP Analysis
        elif packet.haslayer(ICMP):
            self.traffic_metrics['icmp_count'] += 1
            self.protocol_breakdown['ICMP'] += 1
        
        # ARP Analysis
        elif packet.haslayer(ARP):
            self.traffic_metrics['arp_packets'] += 1
            self.protocol_breakdown['ARP'] += 1
        
        else:
            self.traffic_metrics['other_protocols'] += 1
            self.protocol_breakdown['Other'] += 1
        
        # Track source-destination pairs
        if packet.haslayer(IP):
            flow_key = f"{packet[IP].src} -> {packet[IP].dst}"
            self.source_destinations[flow_key] += 1
    
    def print_packet_details(self, timestamp, packet_info, packet):
        """Display comprehensive packet information"""
        print(f"\n[{timestamp}] Packet #{self.traffic_metrics['packet_total']}")
        print(f"  Protocol Layer: {packet_info['protocol_type']}")
        print(f"  Source Address: {packet_info['source_address']}:{packet_info['source_port']}")
        print(f"  Destination: {packet_info['dest_address']}:{packet_info['dest_port']}")
        print(f"  Packet Size: {packet_info['packet_size']} bytes")
        
        if packet_info['data_preview']:
            print(f"  Data Content: {packet_info['data_preview']}")
        
        # Display protocol stack
        try:
            protocol_stack = [layer.__name__ for layer in packet.layers()]
            print(f"  Stack Layers: {' -> '.join(protocol_stack)}")
        except Exception as e:
            print(f"  Stack Layers: {len(packet.layers())} layer(s) detected")
    
    def print_metrics(self):
        """Display comprehensive traffic metrics"""
        print("\n" + "="*60)
        print("TRAFFIC ANALYSIS METRICS")
        print("="*60)
        print(f"Total Packets Captured: {self.traffic_metrics['packet_total']}")
        print(f"\nProtocol Breakdown:")
        print(f"  TCP Packets: {self.traffic_metrics['tcp_count']}")
        print(f"  UDP Packets: {self.traffic_metrics['udp_count']}")
        print(f"  ICMP Packets: {self.traffic_metrics['icmp_count']}")
        print(f"  ARP Packets: {self.traffic_metrics['arp_packets']}")
        print(f"  Other: {self.traffic_metrics['other_protocols']}")
        print(f"\nApplication Layer:")
        print(f"  HTTP Traffic: {self.traffic_metrics['http_traffic']}")
        print(f"  HTTPS Traffic: {self.traffic_metrics['https_traffic']}")
        print(f"  DNS Queries: {self.traffic_metrics['dns_queries']}")
        print(f"  DHCP Activity: {self.traffic_metrics['dhcp_packets']}")
        
        if self.source_destinations:
            print(f"\nTop Traffic Flows:")
            for flow, count in sorted(self.source_destinations.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"  {flow}: {count} packets")
        
        print("="*60)
    
    def begin_capture(self):
        """Initialize and execute packet capture"""
        print("\n" + "="*60)
        print("SEKABERA IBRAHIM - NETWORK TRAFFIC ANALYZER")
        print("="*60)
        print(f"Interface Configuration: {self.network_interface or 'All interfaces'}")
        print(f"Packet Filter Rules: {self.packet_filter or 'No filter applied'}")
        print(f"Capture Limit: {self.max_packets if self.max_packets > 0 else 'Unlimited'}")
        print("Status: Ready - Press Ctrl+C to terminate\n")
        
        try:
            sniff(
                iface=self.network_interface,
                filter=self.packet_filter,
                prn=self.process_packet,
                count=self.max_packets,
                store=0
            )
        except KeyboardInterrupt:
            print("\n\n[NOTICE] Packet capture terminated by operator")
            self.print_metrics()
            self.export_analysis()
    
    def export_analysis(self):
        """Export captured traffic analysis to persistent file"""
        if self.packet_collection:
            export_filename = f"traffic_analysis_sekabera_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(export_filename, 'w') as output_file:
                output_file.write("="*60 + "\n")
                output_file.write("NETWORK TRAFFIC ANALYSIS REPORT\n")
                output_file.write("Analyst: Sekabera Ibrahim\n")
                output_file.write("="*60 + "\n")
                output_file.write(f"Analysis Timestamp: {datetime.now()}\n")
                output_file.write(f"Total Packets Analyzed: {len(self.packet_collection)}\n\n")
                
                output_file.write("DETAILED PACKET ANALYSIS (First 10 Packets):\n")
                output_file.write("-"*60 + "\n\n")
                
                for idx, captured_packet in enumerate(self.packet_collection[:10]):
                    output_file.write(f"Packet #{idx+1}:\n")
                    output_file.write(captured_packet.show(dump=True))
                    output_file.write("\n" + "-"*40 + "\n\n")
            
            print(f"\n[SUCCESS] Analysis exported to: {export_filename}")

def display_available_interfaces():
    """List all network interfaces available on system"""
    available_ifaces = get_if_list()
    print("\nAvailable Network Interfaces:")
    for idx, interface_name in enumerate(available_ifaces):
        try:
            iface_ip = get_if_addr(interface_name)
            print(f"  [{idx}] {interface_name} - IP: {iface_ip}")
        except:
            print(f"  [{idx}] {interface_name}")
    return available_ifaces

def main():
    argument_parser = argparse.ArgumentParser(
        description="Advanced Network Traffic Analysis Tool by Sekabera Ibrahim"
    )
    argument_parser.add_argument(
        "-i", "--interface",
        help="Target network interface for capture"
    )
    argument_parser.add_argument(
        "-f", "--filter",
        help="Berkeley Packet Filter expression"
    )
    argument_parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Maximum packets to capture (0 = unlimited)"
    )
    argument_parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Display available network interfaces"
    )
    argument_parser.add_argument(
        "--version",
        action="version",
        version="Network Traffic Analyzer v2.0 by Sekabera Ibrahim"
    )
    
    parsed_args = argument_parser.parse_args()
    
    # Privilege verification
    if os.geteuid() != 0:
        print("⚠ ERROR: Elevated privileges required!")
        print("Execution Method: sudo python3 network_traffic_analyzer.py")
        sys.exit(1)
    
    if parsed_args.list_interfaces:
        display_available_interfaces()
        return
    
    # Initialize analyzer
    traffic_analyzer = TrafficAnalyzer(
        network_interface=parsed_args.interface,
        packet_filter=parsed_args.filter,
        max_packets=parsed_args.count
    )
    
    # Interface selection guidance
    if not parsed_args.interface:
        print("[INFO] No interface specified. Displaying available options:")
        display_available_interfaces()
        print("\n[INFO] Proceeding with all interfaces...")
    
    # Execute capture session
    traffic_analyzer.begin_capture()

if __name__ == "__main__":
    import os
    main()