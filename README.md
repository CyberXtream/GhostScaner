# Python Network Scanner

## Description
A powerful, multi-threaded network discovery tool built in Python that allows you to scan your local network and identify all connected devices. This tool provides detailed information including IP addresses, MAC addresses, hostnames, and connection status of devices on your network.

## Key Features
- **Fast Network Discovery**: Uses ARP requests to quickly identify devices
- **Detailed Device Information**: Collects IP addresses, MAC addresses, hostnames
- **Live Status Checking**: Verifies if devices are responding via ping
- **Parallel Processing**: Uses multi-threading for faster scans
- **Save Results**: Export scan results to a text file
- **Cross-Platform**: Works on Windows, macOS, and Linux
- **Fallback Mechanisms**: Attempts to work even without low-level network access 

## Prerequisites
- Python 3.6 or higher
- Required Python packages:
  - scapy
  - ipaddress

### Optional Requirements
- **Windows Users**: 
  - Npcap (for full functionality)
  - The scanner will attempt to work without Npcap, but with limited capabilities

## Installation

### Installing Python Dependencies
```bash
pip install scapy
```

### Windows-Specific Setup (Optional but Recommended)
For optimal performance on Windows, install Npcap:
1. Download from [npcap.com](https://npcap.com/#download)
2. During installation, select "Install Npcap in WinPcap API-compatible mode"
3. Restart your computer after installation

## Usage

1. Run the script:
```bash
python network_scanner.py
```

2. Enter your network in CIDR notation (e.g., 192.168.1.0/24)

3. Choose whether to save the results to a file

## Example Output
```
🔐 Enhanced Python Network Scanner
----------------------------------------

[+] Scanning the network: 192.168.1.0/24 ...

[+] Processing results...

IP Address      MAC Address           Hostname             Status     
----------------------------------------------------------------------
192.168.1.1     00:11:22:33:44:55     router.home          Alive      
192.168.1.5     aa:bb:cc:dd:ee:ff     laptop.home          Alive      
192.168.1.10    ff:ee:dd:cc:bb:aa     Unknown              No Response

[✓] Scan complete. 3 devices detected in 2.45 seconds.
```

## How It Works
1. The scanner sends ARP requests to all possible IP addresses in your network
2. For each response, it collects the IP and MAC address
3. It then attempts to resolve the hostname for each device
4. Finally, it checks if each device responds to ping requests

## Troubleshooting

### "WinPcap/Npcap is not installed" Error
- You can install Npcap as described in the Windows-specific setup section
- The scanner will attempt to use a fallback method, but it may be less reliable

### No Devices Found
- Verify your network connection
- Make sure you're using the correct network address in CIDR notation
- Try running the script with administrator/root privileges

### Permission Errors
- On Linux/macOS, try running with sudo: `sudo python network_scanner.py`
- On Windows, run Command Prompt or PowerShell as Administrator

## Security Note
This tool is intended for network administrators to audit their own networks. Using it on networks without permission may violate local laws and regulations.

## License
This project is open source and available under the MIT License.