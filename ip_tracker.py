#!/usr/bin/env python3
import urllib.request
import json
import csv
import sys
import ipaddress
import socket
import argparse
import time

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    RESET = '\033[0m'

API_ENDPOINTS = {
        'ipwhois': 'https://ipwho.is/',
        'ipapi': 'http://ip-api.com/json/'
}

API_TIMEOUT_SECS = 10
API_SUCCESS_KEY = 'success'

RATE_LIMIT_DELAY = 1.5

DEFAULT_BLACKLIST = ['amazon', 'aws', 'digitalocean', 'linode', 'hetzner', 
    'ovh', 'tor', 'cloudflare', 'google', 'vultr', 'choopa', 
    'microsoft', 'azure', 'alibaba', 'tencent', 'hosting', 'datacenter']
 
def normalize_api_response(raw_data, api_engine):
    """
    Standardizes responses from different IP lookup APIs into a unified format.

    Args:
        raw_data (dict): The raw JSON response from the API.
        api_engine (str): The name of the API engine used ('ipwhois' or 'ipapi').

    Returns:
        dict: A flattened dictionary containing standard keys (ip, country, isp, org, etc.)
    """

    normalized = {}
    
    if api_engine == 'ipwhois':
        normalized['success'] = raw_data.get('success', False)
        normalized['ip'] = raw_data.get('ip', 'N/A')
        normalized['country'] = raw_data.get('country', 'Unknown')
        normalized['region'] = raw_data.get('region', 'Unknown')
        normalized['city'] = raw_data.get('city', 'Unknown')
        normalized['isp'] = raw_data.get('connection', {}).get('isp', 'Unknown')
        normalized['org'] = raw_data.get('connection', {}).get('org', 'Unknown')
        normalized['latitude'] = raw_data.get('latitude', 'Unknown')
        normalized['longitude'] = raw_data.get('longitude', 'Unknown')

    elif api_engine == 'ipapi':
        normalized['success'] = (raw_data.get('status') == 'success')
        normalized['ip'] = raw_data.get('query', 'N/A')
        normalized['country'] = raw_data.get('country', 'Unknown')
        normalized['region'] = raw_data.get('regionName', 'Unknown')
        normalized['city'] = raw_data.get('city', 'Unknown')
        normalized['isp'] = raw_data.get('isp', 'Unknown')
        normalized['org'] = raw_data.get('org', 'Unknown')
        normalized['latitude'] = raw_data.get('lat', 'Unknown')
        normalized['longitude'] = raw_data.get('lon', 'Unknown')

    return normalized

def resolve_target(target):
    """
    Attempts to resolve a hostname or domain to its corresponding IPv4 address.
    If the input is already a valid IP, it returns it unchanged.

    Args:
        target (str): The hostname or IP address to resolve.

    Returns:
        str: The resolved IPv4 address, or None if resolution fails.
    """

    try:
        resolved_ip = socket.gethostbyname(target)
        if resolved_ip != target:
            print(f"{Colors.BLUE}[*]{Colors.RESET} Resolved hostname '{target}' to IP: {resolved_ip}")
        return resolved_ip
    except socket.gaierror:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Unable to resolve hostname: {target}")
        return None

def is_valid_public_ip(ip_input):
    """
    Validates if the provided string is a properly formatted, public IPv4/IPv6 address.
    Rejects private (LAN) and loopback (localhost) addresses for security.

    Args:
        ip_input (str): The IP address string to validate.

    Returns:
        bool: True if it's a valid public IP, False otherwise.
    """

    # Verify valid and public ip input
    try:
        # Verify IP object creation
        ip_obj = ipaddress.ip_address(ip_input)
        if ip_obj.is_private or ip_obj.is_loopback:
            print(f"{Colors.YELLOW}[!]{Colors.RESET} The IP {ip_input} is private or loopback")
            return False

        return True

    except ValueError:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Invalid IP format: {ip_input}")
        return False


def get_ip_info(ip_target="", api_engine='ipwhois'):
    """
    Establishes an HTTP/HTTPS connection to the selected IP geolocation API.

    Args:
        ip_target (str, optional): The target IP to look up. Defaults to empty (local IP).
        api_engine (str, optional): The API engine to use ('ipwhois' or 'ipapi').

    Returns:
        dict: The raw JSON response parsed into a Python dictionary, or None if connection fails.
    """

    # The public API we are using
    url = f"{API_ENDPOINTS[api_engine]}{ip_target}"
    print(f"{Colors.BLUE}[*]{Colors.RESET} Establishing connection to {url}...")

    try:
        with urllib.request.urlopen(url, timeout=API_TIMEOUT_SECS) as response:
            return json.loads(response.read())
    except Exception as e:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Connection error: {e}")
        return None

def is_datacenter_isp(isp, org, blacklist):
    """
    Scans the ISP and Organization names against a threat intelligence blacklist.

    Args:
        isp (str): The Internet Service Provider name.
        org (str): The Organization name owning the IP.
        blacklist (list): A list of keywords associated with Datacenters, VPNs, or Proxies.

    Returns:
        bool: True if a match is found in the blacklist, False otherwise.
    """

    combined_text = f"{isp} {org}".lower()
    return any(keyword in combined_text for keyword in blacklist)

def print_info(ip_info, blacklist=None):
    """
    Formats and prints the normalized IP information to the terminal with ANSI colors.
    Triggers the threat intelligence check to warn about Datacenters/VPNs.

    Args:
        ip_info (dict): The normalized dictionary containing the IP data.
        blacklist (list, optional): The list of threat intel keywords to check against.
    """

    ip_response = ip_info.get('ip', 'N/A')
    country_response = ip_info.get('country', 'Unknown')
    region_response = ip_info.get('region', 'Unknown')
    city_response = ip_info.get('city', 'Unknown')
    
    isp_response = ip_info.get('isp', 'Unknown')
    org_response = ip_info.get('org', 'Unknown')

    lat_response = ip_info.get('latitude', 'Unknown')
    lon_response = ip_info.get('longitude', 'Unknown')

    print(f"""
{Colors.GREEN}[+]{Colors.RESET} Target IP: {ip_response}
{Colors.GREEN}[+]{Colors.RESET} Country: {country_response}
{Colors.GREEN}[+]{Colors.RESET} Region: {region_response}
{Colors.GREEN}[+]{Colors.RESET} City: {city_response}
{Colors.GREEN}[+]{Colors.RESET} ISP: {isp_response}
{Colors.GREEN}[+]{Colors.RESET} ORG: {org_response}
{Colors.GREEN}[+]{Colors.RESET} Coordinates: {lat_response}, {lon_response}""")

    if is_datacenter_isp(isp_response, org_response, blacklist):
        print(f"\n{Colors.RED}[!] WARNING: Datacenter or Cloud provider detected (Possible VPN/Proxy){Colors.RESET}")

    print("-" * 50)

def execute_ip_lookup(ip_target="", blacklist=None, verbose=False, api_engine='ipwhois'):
    """
    Orchestrates the complete lifecycle of a single IP lookup:
    Fetch -> Normalize -> Print -> Return.

    Args:
        ip_target (str, optional): The IP address to analyze.
        blacklist (list, optional): Custom threat intel keyword list.
        verbose (bool, optional): If True, prints the raw JSON response before normalizing.
        api_engine (str, optional): The selected API engine.

    Returns:
        dict: The normalized IP data if successful, None otherwise.
    """

    raw_result = get_ip_info(ip_target, api_engine)

    if raw_result is not None:
        if verbose:
            print(f"\n[DEBUG] Raw API Response ({api_engine}):\n{json.dumps(raw_result, indent=2)}")
    
        # Pass the raw data through the Adapter
        normalized_result = normalize_api_response(raw_result, api_engine)

        if normalized_result.get(API_SUCCESS_KEY):
            print_info(normalized_result, blacklist)
            return normalized_result
        else:
            print(f"{Colors.YELLOW}[!]{Colors.RESET} Target IP {ip_target} not found or invalid via {api_engine}.")
            return None
    else:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Empty Information for IP: {ip_target if ip_target else 'Local'}")
        return None

def process_file(file_path, blacklist=None, verbose=False, api_engine='ipwhois'):
    """
    Reads a file containing IPs or Hostnames, resolves them, and processes them sequentially.

    Args:
        file_path (str): The path to the text file containing the targets.
        blacklist (list, optional): Custom threat intel keyword list.
        verbose (bool, optional): If True, prints raw JSON responses.
        api_engine (str, optional): The selected API engine.

    Returns:
        list: A list of dictionaries containing the normalized results for all processed targets.
    """

    print(f"{Colors.BLUE}[*]{Colors.RESET} Reading IP file: {file_path}")
    processed = 0
    skipped = 0

    results_list = []

    try:
        with open(file_path, 'r') as file:

            for line in file:
                target_ip = line.strip()

                if not target_ip or target_ip.startswith('#'):
                    continue

                print(f"\n--- Researching: {target_ip} ---")

                resolved_ip = resolve_target(target_ip)

                if resolved_ip and is_valid_public_ip(resolved_ip):
                    result_data = execute_ip_lookup(resolved_ip, blacklist, verbose, api_engine)
                    if result_data:
                        results_list.append(result_data)
                    processed += 1
                    time.sleep(RATE_LIMIT_DELAY)
                else:
                    skipped += 1

        total = processed + skipped
        print(f"\n[+] Done -- Processed: {processed} | Skipped: {skipped} | Total: {total}")
        return results_list

    except FileNotFoundError:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Error: The file was not found: '{file_path}'")

def load_custom_blacklist(file_path):
    """
    Loads a custom list of threat intelligence keywords from a local text file.

    Args:
        file_path (str): The path to the custom blacklist .txt file.

    Returns:
        list: A list of lowercase keywords, or None if the file is not found.
    """

    custom_list = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                keyword = line.strip().lower()
                if keyword:
                    custom_list.append(keyword)
        print(f"{Colors.BLUE}[*]{Colors.RESET} Loaded custom blacklist with {len(custom_list)} keywords.")
        return custom_list
    except FileNotFoundError:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} Error: Custom blacklist file '{file_path}' not found. Using default list")
        return None

def export_results(results, format_type):
    """
    Exports the gathered intelligence into a structured CSV or JSON file.
    Automatically appends a timestamp to the filename to prevent overwriting.

    Args:
        results (list): A list of dictionaries containing the normalized IP data.
        format_type (str): The desired output format ('csv' or 'json').
    """

    if not results:
        print(f"{Colors.YELLOW}[!]{Colors.RESET} No valid data to export.")
        return
        
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    filename = f"tracker_report_{timestamp}.{format_type}"
    print(f"\n{Colors.BLUE}[*]{Colors.RESET} Exporting {len(results)} results to {filename}...")
    
    if format_type == 'json':
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
            
    elif format_type == 'csv':
        keys = results[0].keys()
        with open(filename, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, fieldnames=keys)
            dict_writer.writeheader()
            dict_writer.writerows(results)
            
    print(f"{Colors.GREEN}[+]{Colors.RESET} Export complete: {filename}")

if __name__ == "__main__":
    # Parser Definition
    parser = argparse.ArgumentParser(description="IP Tracker OSINT Tool")
    parser.add_argument('-i', '--input_ip', type=str, help='Specific input IP')
    parser.add_argument('-f', '--file', type=str, help='IP file to process')
    parser.add_argument('-b', '--blacklist', type=str, help='Custom ISP blacklist file (.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (print raw API JSON)')
    parser.add_argument('--api', type=str, choices=['ipwhois', 'ipapi'], default='ipwhois', help='Select the API engine (default: ipwhois with TLS)')
    parser.add_argument('-o', '--output', nargs='?', const='csv', choices=['csv', 'json'], help='Export results to a file (default format: csv)')

    # Read user args
    args = parser.parse_args()

    # API Security Check
    if args.api == 'ipapi':
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} WARNING: You selected the 'ipapi' engine which uses unencrypted HTTP.")
        print("Your traffic (including the IPs you track) could be intercepted (MITM).")
        consent = input("Do you want to proceed without TLS? [y/N]: ").strip().lower()
        if consent != 'y':
            print(f"{Colors.BLUE}[*]{Colors.RESET} Operation cancelled by the user. Enforcing secure defaults.")
            sys.exit(0)
    
    # Load Custom Blacklist
    active_blacklist = DEFAULT_BLACKLIST
    if args.blacklist:
        loaded_list = load_custom_blacklist(args.blacklist)
        if loaded_list is not None:
            active_blacklist = loaded_list

    # Routing
    if args.file:
        collected_data = process_file(args.file, active_blacklist, args.verbose, args.api)
        if args.output and collected_data:
            export_results(collected_data, args.output)

    elif args.input_ip:
        resolved_ip = resolve_target(args.input_ip)
        if not resolved_ip or not is_valid_public_ip(resolved_ip):
            sys.exit(1)

        result_data = execute_ip_lookup(resolved_ip, active_blacklist, args.verbose, args.api)
        
        if args.output and result_data:
            export_results([result_data], args.output)

    else:
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} WARNING: You are about to query your local machine's public IP.")
        print("This will expose your IP to a third-party API (ipwho.is).")
        consent = input("Do you want to proceed? [y/N]: ").strip().lower()

        if consent == 'y':
            result_data = execute_ip_lookup("", active_blacklist, args.verbose, args.api)
            if args.output and result_data:
                export_results([result_data], args.output)
        else:
            print(f"{Colors.BLUE}[*]{Colors.RESET} Operation cancelled by the user. Stay safe.")
            sys.exit(0)
