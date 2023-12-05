import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading

def ping_scan(target):
    subprocess.run(f"nmap -sn {target} -oG - | awk '/Up$/{{print $2}}' > live_hosts.txt", shell=True, check=True)

def detailed_scan(host, output_file, lock):
    print(f"Scanning {host}")
    result = subprocess.run(f"nmap -O {host} -oN -", shell=True, check=True, capture_output=True, text=True)
    
    # Acquire the lock before writing to the file
    with lock:
        with open(output_file, "a") as f:
            f.write(f"Scan for {host}:\n{result.stdout}\n\n")
    
    print(result.stderr)
    print(f"{host} scanned.\n\n")

# Prompt the user for the target IP range
target_range = input("Enter the target IP range (e.g., 192.168.1.0/24): ")

# File to store the list of live hosts
live_hosts_file = "live_hosts.txt"

# File to store the detailed scan results
detailed_scan_file = "detailed_scan_results.txt"

# Perform a ping scan to identify live hosts
print("Scanning for live hosts...")
ping_scan(target_range)

# Check if live hosts were found
with open(live_hosts_file) as f:
    live_hosts = f.read().splitlines()

if live_hosts:
    print("Live hosts found. Performing detailed scans...")

    # Perform detailed scan on live hosts using ThreadPoolExecutor
    lock = threading.Lock()
    with open(detailed_scan_file, "w") as output_file:
        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(detailed_scan, host, detailed_scan_file, lock) for host in live_hosts]

    print(f"Scan completed. Detailed results saved in {detailed_scan_file}")
else:
    print("No live hosts found.")
