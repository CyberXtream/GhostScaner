from scapy.all import ARP, Ether, srp, conf
import socket
import subprocess
import ipaddress
import concurrent.futures
import time
import sys
import os

def check_requirements():
    """Check if required dependencies are installed"""
    try:
        # Test if we can create and use a layer 2 socket
        from scapy.arch import get_if_list
        if not get_if_list():
            print("[!] Error: No network interfaces found.")
            return False
            
        # Try to send a test packet to loopback
        test_result = srp(Ether()/ARP(), timeout=0.1, verbose=0)
        return True
    except OSError as e:
        if "winpcap" in str(e).lower():
            print("[!] Error: WinPcap/Npcap is not installed.")
            print("[+] Please install Npcap from: https://npcap.com/#download")
            print("[+] Make sure to select 'Install Npcap in WinPcap API-compatible mode'")
            return False
        else:
            print(f"[!] Network error: {str(e)}")
            return False
    except Exception as e:
        print(f"[!] Initialization error: {str(e)}")
        return False

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def is_alive(ip):
    try:
        # ping -c 1 for Linux/Mac, -n 1 for Windows
        param = '-n' if subprocess.run("ver", shell=True, capture_output=True).returncode == 0 else '-c'
        output = subprocess.run(['ping', param, '1', ip], capture_output=True, timeout=1)
        return output.returncode == 0
    except:
        return False

def get_device_info(sent_received):
    sent, received = sent_received
    ip = received.psrc
    mac = received.hwsrc
    hostname = get_hostname(ip)
    alive = is_alive(ip)
    return {'ip': ip, 'mac': mac, 'hostname': hostname, 'alive': alive}

def scan_network(router_ip_with_cidr):
    try:
        # Validate the CIDR notation
        network = ipaddress.IPv4Network(router_ip_with_cidr, strict=False)
        
        arp = ARP(pdst=router_ip_with_cidr)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        print(f"\n[+] Scanning the network: {router_ip_with_cidr} ...\n")
        start_time = time.time()
        
        try:
            # First try with layer 2
            result = srp(packet, timeout=3, verbose=0, retry=1)[0]
        except OSError as e:
            if "winpcap" in str(e).lower():
                print("[!] WinPcap/Npcap not detected. Attempting to use Layer 3 socket instead...")
                # Fall back to Layer 3 socket
                conf.L3socket = conf.L3socket
                # Use ARP scan directly without Ethernet frame
                result = ARP().pdst(router_ip_with_cidr).sr(timeout=3, verbose=0, retry=1)[0]
            else:
                raise
        
        if not result:
            print("[!] No devices found. Check your network connection and try again.")
            return []

        print("[+] Processing results...")
        
        # Use ThreadPoolExecutor to get device info in parallel
        devices = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            devices = list(executor.map(get_device_info, result))

        # Format output in a proper table
        print("\n{:<16} {:<20} {:<20} {:<12}".format("IP Address", "MAC Address", "Hostname", "Status"))
        print("-" * 70)
        for d in devices:
            status = "Alive" if d['alive'] else "No Response"
            hostname = d['hostname'][:15] if len(d['hostname']) > 15 else d['hostname']
            print("{:<16} {:<20} {:<20} {:<12}".format(d['ip'], d['mac'], hostname, status))

        scan_time = time.time() - start_time
        print(f"\n[✓] Scan complete. {len(devices)} devices detected in {scan_time:.2f} seconds.")
        
        return devices
    except Exception as e:
        print(f"[!] Scan error: {str(e)}")
        return []

def save_results_to_file(devices, filename="scan_results.txt"):
    try:
        with open(filename, 'w') as f:
            f.write("{:<16} {:<20} {:<20} {:<12}\n".format("IP Address", "MAC Address", "Hostname", "Status"))
            f.write("-" * 70 + "\n")
            for d in devices:
                status = "Alive" if d['alive'] else "No Response"
                hostname = d['hostname'][:15] if len(d['hostname']) > 15 else d['hostname']
                f.write("{:<16} {:<20} {:<20} {:<12}\n".format(d['ip'], d['mac'], hostname, status))
        return True
    except Exception as e:
        print(f"[!] Error saving results: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔐 Enhanced Python Network Scanner")
    print("-" * 40)
    
    try:
        # Check if Npcap/WinPcap is installed
        if not check_requirements():
            print("\n[!] Please install the required dependencies and try again.")
            sys.exit(1)
            
        router_cidr = input("Enter your router IP with CIDR (e.g. 192.168.1.1/24): ").strip()
        
        # Validate input before scanning
        ipaddress.IPv4Network(router_cidr, strict=False)
        
        # Ask if user wants to save results
        save_option = input("Would you like to save results to a file? (y/n): ").lower().strip()
        
        devices = scan_network(router_cidr)
        
        if devices and save_option == 'y':
            filename = input("Enter filename (default: scan_results.txt): ").strip() or "scan_results.txt"
            if save_results_to_file(devices, filename):
                print(f"[✓] Results saved to {filename}")
            
    except ValueError:
        print("[!] Invalid CIDR format. Example: 192.168.1.1/24")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
    except Exception as e:
        print(f"\n[!] An error occurred: {str(e)}")
        