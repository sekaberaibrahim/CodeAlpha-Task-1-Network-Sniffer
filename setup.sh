#!/bin/bash

################################################################################
# SEKABERA IBRAHIM -  NETWORK TRAFFIC ANALYZER
# Installation & Configuration Script
# CodeAlpha Cybersecurity Internship Program
# Developer: Sekabera Ibrahim
# GitHub: https://github.com/sekaberaibrahim
################################################################################
# Administrative privilege verification
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  NOTICE: Administrator privileges recommended for full functionality"
   echo "   Execute with elevated rights: sudo ./initialize.sh"
   echo ""
fi

# ============================================================================
# PYTHON ENVIRONMENT VERIFICATION
# ============================================================================

echo "🔍 SYSTEM DIAGNOSTICS - Python Environment"
echo "─────────────────────────────────────────────────────────────────"

python_check=$(python3 --version 2>&1)
if [[ $? -eq 0 ]]; then
    echo "✅ Python Interpreter: $python_check"
else
    echo "❌ CRITICAL: Python 3 environment not detected"
    echo "   Installation required: apt install python3"
    exit 1
fi

# ============================================================================
# DEPENDENCY MANAGER VERIFICATION
# ============================================================================

echo ""
echo "📦 DEPENDENCY VERIFICATION - Package Manager"
echo "─────────────────────────────────────────────────────────────────"

pip_check=$(pip3 --version 2>&1)
if [[ $? -eq 0 ]]; then
    echo "✅ Package Manager: $pip_check"
else
    echo "⚠️  WARNING: pip3 not detected in system PATH"
    echo "   Attempting automatic installation..."
    
    if [[ $EUID -eq 0 ]]; then
        apt update && apt install -y python3-pip
        if [[ $? -eq 0 ]]; then
            echo "✅ Package manager installed successfully"
        else
            echo "❌ Automatic installation failed"
            exit 1
        fi
    else
        echo "❌ Installation requires root privileges"
        echo "   Please execute: sudo ./initialize.sh"
        exit 1
    fi
fi

# ============================================================================
# LIBRARY DEPENDENCY INSTALLATION
# ============================================================================

echo ""
echo "🔧 LIBRARY DEPLOYMENT - Installing Required Packages"
echo "─────────────────────────────────────────────────────────────────"

if [[ -f "requirements.txt" ]]; then
    echo "📋 Reading dependency manifest: requirements.txt"
    pip3 install -r requirements.txt --upgrade
    
    if [[ $? -eq 0 ]]; then
        echo "✅ Library installation completed successfully"
    else
        echo "❌ Library installation encountered errors"
        echo "   Try manual installation: pip3 install scapy psutil colorama"
        exit 1
    fi
else
    echo "⚠️  Dependency manifest not found - Installing core libraries..."
    pip3 install scapy>=2.4.5 psutil>=5.9.0 colorama>=0.4.4
    
    if [[ $? -eq 0 ]]; then
        echo "✅ Core libraries installed successfully"
    else
        echo "❌ Core library installation failed"
        exit 1
    fi
fi

# ============================================================================
# EXECUTABLE PERMISSION CONFIGURATION
# ============================================================================

echo ""
echo "🔐 PERMISSION MANAGEMENT - Setting File Permissions"
echo "─────────────────────────────────────────────────────────────────"

chmod +x network_traffic_analyzer.py
if [[ $? -eq 0 ]]; then
    echo "✅ Execution permissions configured"
else
    echo "⚠️  Permission configuration encountered issues"
fi

chmod +x initialize.sh
echo "✅ Script permissions updated"

# ============================================================================
# FRAMEWORK VALIDATION
# ============================================================================

echo ""
echo "🧪 VALIDATION - Scapy Framework Integration Test"
echo "─────────────────────────────────────────────────────────────────"

python3 -c "
import sys
try:
    import scapy
    from scapy.all import sniff, IP, TCP, UDP
    print('✅ Scapy Framework: Successfully imported')
    print('   Version:', scapy.__version__)
    sys.exit(0)
except ImportError as e:
    print('❌ Scapy Import Failed:', str(e))
    sys.exit(1)
" 2>/dev/null

if [[ $? -ne 0 ]]; then
    echo "❌ Scapy framework validation failed"
    echo "   Reinstalling: pip3 install --force-reinstall scapy"
    pip3 install --force-reinstall scapy
    exit 1
fi

# ============================================================================
# ADDITIONAL MODULES VERIFICATION
# ============================================================================

echo ""
echo "✓ Validating supplementary modules..."

python3 -c "
try:
    import psutil
    print('✅ psutil (System monitoring): Available')
except:
    print('⚠️  psutil: Not installed (optional)')
" 2>/dev/null

python3 -c "
try:
    import colorama
    print('✅ colorama (Terminal colors): Available')
except:
    print('⚠️  colorama: Not installed (optional)')
" 2>/dev/null

# ===========================================================================
# PLATFORM DETECTION & RECOMMENDATIONS
# ===========================================================================

echo ""
echo "🖥️  PLATFORM ANALYSIS - Operating System Detection"
echo "─────────────────────────────────────────────────────────────────"

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "✅ Operating System: Linux Kernel"
    echo ""
    echo "   CONFIGURATION NOTES:"
    echo "   • Raw socket access requires elevated privileges (sudo)"
    echo "   • Verify libpcap installation: apt install libpcap-dev"
    echo "   • Execute with: sudo python3 network_traffic_analyzer.py"
    echo ""
    
    # Check for libpcap
    if dpkg -l | grep -q libpcap-dev; then
        echo "   ✅ libpcap development library: Detected"
    else
        echo "   ⚠️  libpcap-dev: Not detected (recommended)"
        if [[ $EUID -eq 0 ]]; then
            echo "   Installing libpcap-dev..."
            apt install -y libpcap-dev
        fi
    fi
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "✅ Operating System: macOS (Darwin)"
    echo ""
    echo "   CONFIGURATION NOTES:"
    echo "   • Raw socket access requires elevated privileges (sudo)"
    echo "   • Install libpcap via Homebrew: brew install libpcap"
    echo "   • Execute with: sudo python3 network_traffic_analyzer.py"
    echo ""
    
elif [[ "$OSTYPE" == "msys" ]]; then
    echo "⚠️  Operating System: Windows Environment Detected"
    echo ""
    echo "   COMPATIBILITY NOTICE:"
    echo "   • Windows support requires additional drivers"
    echo "   • Download and install: https://nmap.org/npcap/"
    echo "   • Recommend using Windows Subsystem for Linux (WSL)"
    echo ""
    
else
    echo "❓ Operating System: Unidentified ($OSTYPE)"
    echo "   Kali Linux / Linux environment recommended"
    echo ""
fi

# ============================================================================
# NETWORK INTERFACE DISCOVERY
# ============================================================================

echo ""
echo "🌐 NETWORK INTERFACE ENUMERATION"
echo "─────────────────────────────────────────────────────────────────"

if [[ $EUID -eq 0 ]]; then
    echo "Available network interfaces:"
    echo ""
    python3 -c "
from scapy.all import get_if_list, get_if_addr
try:
    interfaces = get_if_list()
    for idx, iface in enumerate(interfaces):
        try:
            ip_addr = get_if_addr(iface)
            print(f'   [{idx}] {iface:12} IP: {ip_addr}')
        except:
            print(f'   [{idx}] {iface:12} (IP not assigned)')
except Exception as e:
    print(f'   Error retrieving interfaces: {e}')
" 2>/dev/null
else
    echo "⚠️  Run with sudo to display network interfaces"
    echo "   Command: sudo python3 network_traffic_analyzer.py --list-interfaces"
fi

# ============================================================================
# INSTALLATION COMPLETION STATUS
# ============================================================================

echo ""
echo "████████████████████████████████████████████████████████████████"
echo "🎉 INSTALLATION COMPLETED SUCCESSFULLY"
echo "████████████████████████████████████████████████████████████████"
echo ""

# ============================================================================
# USAGE GUIDE
# ============================================================================

echo "📖 QUICK START GUIDE"
echo "─────────────────────────────────────────────────────────────────"
echo ""
echo "  1️⃣  List Available Interfaces:"
echo "      sudo python3 network_traffic_analyzer.py --list-interfaces"
echo ""
echo "  2️⃣  Capture Initial Packets (10 packet limit, all interfaces):"
echo "      sudo python3 network_traffic_analyzer.py -c 10"
echo ""
echo "  3️⃣  Analyze DNS Traffic (5 packet limit):"
echo "      sudo python3 network_traffic_analyzer.py -f 'udp port 53' -c 5"
echo ""
echo "  4️⃣  Monitor HTTP Traffic:"
echo "      sudo python3 network_traffic_analyzer.py -f 'tcp port 80' -c 10"
echo ""
echo "  5️⃣  Capture on Specific Interface:"
echo "      sudo python3 network_traffic_analyzer.py -i eth0 -c 20"
echo ""
echo "  6️⃣  ICMP Echo Analysis:"
echo "      sudo python3 network_traffic_analyzer.py -f 'icmp' -c 5"
echo ""

# ============================================================================
# SECURITY & LEGAL COMPLIANCE
# ============================================================================

echo "🛡️  SECURITY & ETHICAL CONSIDERATIONS"
echo "─────────────────────────────────────────────────────────────────"
echo ""
echo "⚠️  CRITICAL COMPLIANCE REQUIREMENTS:"
echo ""
echo "  • AUTHORIZATION: Only monitor networks with explicit written permission"
echo "  • LEGAL COMPLIANCE: Unauthorized monitoring may violate laws"
echo "  • ETHICAL USAGE: Restrict use to authorized security testing only"
echo "  • DATA SENSITIVITY: Handle captured information with appropriate care"
echo "  • DOCUMENTATION: Maintain records of all analysis activities"
echo ""
echo "  ⛔ Unauthorized use is illegal and unethical"
echo ""

# ===========================================================================
# RESOURCES & DOCUMENTATION
# ===========================================================================

echo "📚 DOCUMENTATION & RESOURCES"
echo "─────────────────────────────────────────────────────────────────"
echo ""
echo "  📄 README File:"
echo "     See README.md for comprehensive documentation"
echo ""
echo "  🔬 Technical Report:"
echo "     Full analysis available in documentation/"
echo ""
echo "  💻 Source Code:"
echo "     GitHub: https://github.com/sekaberaibrahim"
echo ""
echo "  🎓 CodeAlpha Program:"
echo "     https://www.codealpha.tech"
echo ""

# ============================================================================
# DEVELOPER INFORMATION
# ============================================================================

echo "👤 DEVELOPER INFORMATION"
echo "─────────────────────────────────────────────────────────────────"
echo ""
echo "  Developer: Sekabera Ibrahim"
echo "  Program: CodeAlpha Cybersecurity Internship"
echo "  GitHub: @sekaberaibrahim"
echo "  Project: Advanced Network Traffic Analyzer"
echo ""

echo "████████████████████████████████████████████████████████████████"
echo "🚀 Ready to analyze network traffic!"
echo "████████████████████████████████████████████████████████████████"
echo ""
