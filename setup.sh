#!/bin/bash

# CodeAlpha Network Sniffer Setup Script
# Task 1: Basic Network Sniffer
# Author: FarahMae

echo "======================================"
echo "CodeAlpha Network Sniffer Setup"
echo "Task 1: Basic Network Sniffer"
echo "======================================"
echo

# Check if running as root for dependency installation
if [[ $EUID -ne 0 ]]; then
   echo "⚠️  Note: Root privileges may be required for some operations"
   echo "   You can run: sudo ./setup.sh"
   echo
fi

# Check Python version
echo "🐍 Checking Python version..."
python3_version=$(python3 --version 2>&1)
if [[ $? -eq 0 ]]; then
    echo "✅ $python3_version found"
else
    echo "❌ Python 3 not found. Please install Python 3.6 or higher"
    exit 1
fi

# Check pip
echo "📦 Checking pip..."
pip3_version=$(pip3 --version 2>&1)
if [[ $? -eq 0 ]]; then
    echo "✅ pip3 found"
else
    echo "❌ pip3 not found. Installing..."
    if [[ $EUID -eq 0 ]]; then
        apt update && apt install -y python3-pip
    else
        echo "Please install pip3 manually or run as root"
        exit 1
    fi
fi

# Install dependencies
echo "🔧 Installing dependencies..."
if [[ -f "requirements.txt" ]]; then
    pip3 install -r requirements.txt
    if [[ $? -eq 0 ]]; then
        echo "✅ Dependencies installed successfully"
    else
        echo "❌ Failed to install dependencies"
        exit 1
    fi
else
    echo "Installing scapy directly..."
    pip3 install scapy
fi

# Make scripts executable
echo "🔐 Setting permissions..."
chmod +x network_sniffer.py

# Check scapy installation
echo "🧪 Testing scapy installation..."
python3 -c "import scapy; print('✅ Scapy imported successfully')" 2>/dev/null
if [[ $? -ne 0 ]]; then
    echo "❌ Scapy import failed. Please check installation"
    exit 1
fi

# Platform-specific notes
echo
echo "📋 Platform-specific notes:"
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "   🐧 Linux detected"
    echo "   • Run with sudo for raw socket access"
    echo "   • Test with: sudo python3 network_sniffer.py --list-interfaces"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "   🍎 macOS detected"
    echo "   • Run with sudo for raw socket access"
    echo "   • Test with: sudo python3 network_sniffer.py --list-interfaces"
else
    echo "   ❓ Unknown OS - Linux/Unix environment recommended"
fi

echo
echo "🎉 Setup completed successfully!"
echo
echo "📖 Quick start:"
echo "   1. List interfaces:    sudo python3 network_sniffer.py --list-interfaces"
echo "   2. Capture 10 packets: sudo python3 network_sniffer.py -c 10"
echo "   3. Filter DNS traffic: sudo python3 network_sniffer.py -f 'udp port 53' -c 5"
echo
echo "⚠️  Security reminder:"
echo "   Only use this tool on networks you own or have explicit permission to monitor."
echo "   Unauthorized network monitoring may violate laws and regulations."
echo
echo "🔗 For detailed usage instructions, see README.md"
echo "======================================"
