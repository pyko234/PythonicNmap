import subprocess
from concurrent.futures import ThreadPoolExecutor
import threading
import pandas as pd
import os

# File to store the list of live hosts
live_hosts_file = "live_hosts.txt"

# File to store the detailed scan results
detailed_scan_file = "detailed_scan_results.txt"

# File to store the parsed results in CSV format
parsed_results_file = "parsed_results.csv"

def ping_scan(target):
    subprocess.run(f"nmap -sn {target} -oG - | awk '/Up$/{{print $2}}' > live_hosts.txt", shell=True, check=True)

def detailed_scan(host, output_file, lock):
    print(f"Scanning {host}")
    result = subprocess.run(f"nmap -O {host} -oN -", shell=True, check=True, capture_output=True, text=True)
    
    # Acquire the lock before writing to the file
    with lock:
        with open(output_file, "a") as f:
            f.write(f"Scan for {host}:\n{result.stdout}\n\n")

def comprehensive_scan():
    # Prompt the user for the target IP range
    target_range = input("Enter the target IP range (e.g., 192.168.1.0/24): ")

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

def parse_results_to_dataframe(file_path):
    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return None

    with open(file_path, "r") as f:
        data = f.read()

    # Split data into individual scan results
    scan_results = data.split("Scan for ")[1:]

    # Create a list to store dictionaries representing each scan result
    parsed_data = []
    for scan_result in scan_results:
        # Split each scan result into lines
        lines = scan_result.split("\n")
        if lines:
            # Extract IP address and details
            ip_address = lines[0].strip(":")
            details = "\n".join(lines[1:])
            
            # Append to parsed_data list
            parsed_data.append({"Host": ip_address, "Details": details})

    # Create a Pandas DataFrame
    df = pd.DataFrame(parsed_data)
    return df

def main():
    comprehensive_scan()

    # Parse detailed scan results to a Pandas DataFrame
    df = parse_results_to_dataframe(detailed_scan_file)

    # Save the DataFrame to a CSV file
    df.to_csv(parsed_results_file, index=False)
    print(f"Parsed results saved in {parsed_results_file}")

if __name__ == '__main__':
    main()
