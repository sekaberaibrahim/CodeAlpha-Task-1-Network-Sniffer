# CodeAlpha_Task1: NetworkSniffer

![Status](https://img.shields.io/badge/Status-Completed-brightgreen)
![Platform](https://img.shields.io/badge/Platform-KaliLinux|Python3-blue)
![Type](https://img.shields.io/badge/Type-NetworkSniffer-orange)
![Protocols](https://img.shields.io/badge/Protocols-TCP_UDP_ICMP_DNS_HTTP_HTTPS-lightgrey)
![Filter](https://img.shields.io/badge/Filter-BPF-informational)
![Level](https://img.shields.io/badge/Level-Professional-critical)
![License](https://img.shields.io/badge/License-Educational-important)


##  Cybersecurity Internship - Task 1: Basic Network Sniffer

A professional-grade network packet analyzer built for educational cybersecurity purposes. This tool demonstrates comprehensive understanding of network protocols, security implications, and practical network forensics capabilities.

###  Project Overview

**Internship:** CodeAlpha Cybersecurity Program  
**Task:** Task 1 - Basic Network Sniffer  
**Technologies:** Python 3, Scapy, Linux  
**Platform:** Kali Linux (Recommended)  

###  Features

- **Multi-Protocol Support:** TCP, UDP, ICMP, DNS, HTTP, HTTPS, ARP, DHCP
- **Real-time Analysis:** Live packet capture and display
- **Security-Aware:** Demonstrates encryption vs plain-text differences
- **Professional Logging:** Detailed packet analysis and statistics
- **Filter Support:** Berkeley Packet Filter (BPF) integration
- **Educational Focus:** Clear protocol layer visualization

###  Quick Start

#### Prerequisites
```bash
# Ensure Python 3.6+ is installed
python3 --version

# Install required dependencies
sudo apt update
sudo apt install python3-pip
sudo pip3 install scapy
```

#### Installation
```bash
# Clone the repository
git clone https://github.com/FarahMae/CodeAlpha-Task-1---Network-Sniffer.git
cd CodeAlpha-Task-1---Network-Sniffer

# Make executable
chmod +x network_sniffer.py
chmod +x setup.sh

# Run setup script (optional)
sudo ./setup.sh
```

#### Basic Usage
```bash
# List available network interfaces
sudo python3 network_sniffer.py --list-interfaces

# Capture 10 packets on all interfaces
sudo python3 network_sniffer.py -c 10

# Capture on specific interface
sudo python3 network_sniffer.py -i eth0 -c 20

# Filter specific traffic
sudo python3 network_sniffer.py -f "tcp port 80" -c 5
```

###  Usage Examples

#### DNS Traffic Analysis
```bash
# Terminal 1: Start DNS capture
sudo python3 network_sniffer.py -f "udp port 53" -c 5

# Terminal 2: Generate DNS traffic
nslookup google.com
```

#### HTTP vs HTTPS Comparison
```bash
# Capture HTTP traffic (readable)
sudo python3 network_sniffer.py -f "tcp port 80" -c 5

# Capture HTTPS traffic (encrypted)
sudo python3 network_sniffer.py -f "tcp port 443" -c 5
```

#### ICMP Analysis
```bash
# Capture ping packets
sudo python3 network_sniffer.py -f "icmp" -c 5

# Generate ping traffic (in another terminal)
ping -c 3 8.8.8.8
```

###  Command Line Options

| Option | Description | Example |
|--------|-------------|---------|
| `-i, --interface` | Specify network interface | `-i eth0` |
| `-f, --filter` | BPF filter expression | `-f "tcp port 80"` |
| `-c, --count` | Number of packets to capture | `-c 50` |
| `--list-interfaces` | Show available interfaces | `--list-interfaces` |

###  Sample Output

```
[12:45:32] Packet #1
  Protocol: DNS
  Source: 10.0.2.4:42278
  Destination: 10.0.0.138:53
  Length: 70 bytes
  Payload Preview: DNS Query: google.com.
  Layers: Ether -> IP -> UDP -> DNS

[12:45:32] Packet #2
  Protocol: HTTP
  Source: 10.0.2.4:44328
  Destination: 23.192.228.80:80
  Length: 129 bytes
  Payload Preview: GET / HTTP/1.1\r\nHost: example.com
  Layers: Ether -> IP -> TCP -> Raw
```

### 🛡 Security Considerations

**Important Notes:**
- ⚠ **Legal Compliance:** Only use on networks you own or have explicit permission to monitor
-  **Ethical Usage:** Educational and legitimate security testing only
-  **Privacy Respect:** Be mindful of capturing sensitive information
-  **Documentation:** Always document testing activities

**What the Tool Reveals:**
- HTTP traffic exposes all data in plain text
- HTTPS provides complete data protection
- DNS queries reveal browsing patterns
- Background tracking is extensive and often hidden

###  Educational Value

#### Network Protocols Demonstrated
- **Layer 2:** Ethernet, ARP (Address Resolution)
- **Layer 3:** IP, ICMP (Internet Control)
- **Layer 4:** TCP, UDP (Transport Layer)
- **Application:** HTTP, HTTPS, DNS, DHCP

#### Security Concepts
- **Encryption vs Plain Text:** HTTP vs HTTPS comparison
- **Network Forensics:** Traffic pattern analysis
- **Privacy Implications:** Third-party tracking detection
- **Attack Vectors:** Man-in-the-middle vulnerabilities

#### Real-World Insights
```
Typical capture session reveals:
├── Infrastructure: DHCP, ARP, DNS
├── Web Traffic: HTTP, HTTPS, background updates
├── Security: Encrypted vs unencrypted data
└── Privacy: Advertising and tracking networks
```

###  Technical Architecture

```
Network Interface
        ↓
Raw Packet Capture (Scapy)
        ↓
Protocol Analysis Engine
        ↓
├── Layer Detection
├── Payload Analysis
├── Security Assessment
└── Statistical Tracking
        ↓
Real-time Display & Logging
```

###  Testing Results

Our comprehensive testing revealed:

**Protocol Coverage:**
- ✅ ICMP: Bidirectional ping analysis
- ✅ DNS: IPv4/IPv6 dual-stack queries
- ✅ HTTP: Complete plain-text exposure
- ✅ HTTPS: Strong encryption validation
- ✅ Background: DHCP, ARP, tracking networks

**Security Findings:**
- HTTP exposes 100% of data to network sniffers
- Modern web browsing involves 10+ third-party services
- DNS queries reveal all browsing activity
- HTTPS effectively protects application data

###  Future Enhancements

**Planned Features:**
- [ ] Web-based GUI dashboard
- [ ] Machine learning traffic analysis
- [ ] Integration with threat intelligence feeds
- [ ] Automated vulnerability detection
- [ ] PCAP file export capability

###  Documentation

- **Technical Report:** Complete analysis and findings in `docs/` folder
- **Code Comments:** Comprehensive inline documentation
- **Usage Examples:** Real-world testing scenarios
- **Security Assessment:** Protocol vulnerability analysis

###  Contributing

This project is part of the CodeAlpha cybersecurity internship program. Contributions, suggestions, and educational improvements are welcome!

###  License

This project is for educational purposes as part of the CodeAlpha internship program. Please respect ethical usage guidelines and legal requirements for network monitoring.

###  Links

- **CodeAlpha:** [www.codealpha.tech](https://www.codealpha.tech)
- **LinkedIn:** [Tag @CodeAlpha in your project post]
- **Documentation:** See `docs/technical_report.md` for detailed analysis

###  Author

**FarahMae**  
CodeAlpha Cybersecurity Intern  
[[LinkedIn Profile](https://www.linkedin.com/in/farah-mae-sumajit-a03493303/)]  

---

** If this project helped you understand network security, please star this repository!**

*Built with  for cybersecurity education and professional development.*
