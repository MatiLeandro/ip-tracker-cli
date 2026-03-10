#!/usr/bin/env python3
import urllib.request
import json
import sys
import ipaddress
import argparse
import time

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

def is_valid_public_ip(ip_input):
    # Verify valid and public ip input
    try:
        # Verify IP object creation
        ip_obj = ipaddress.ip_address(ip_input)
        if ip_obj.is_private or ip_obj.is_loopback:
            print(f"[!] The IP {ip_input} is private or loopback")
            return False

        return True

    except ValueError:
        print(f"[!] Invalid IP format: {ip_input}")
        return False


def get_ip_info(ip_target="", api_engine='ipwhois'):
    # The public API we are using
    url = f"{API_ENDPOINTS[api_engine]}{ip_target}"
    print(f"[*] Establishing connection to {url}...")

    try:
        with urllib.request.urlopen(url, timeout=API_TIMEOUT_SECS) as response:
            return json.loads(response.read())
    except Exception as e:
        print(f"[!] Connection error: {e}")
        return None

def is_datacenter_isp(isp, blacklist):
    isp_lower = isp.lower()
    return any(keyword in isp_lower for keyword in blacklist)

def print_info(ip_info, blacklist=None):

    ip_response = ip_info.get('ip', 'N/A')
    country_response = ip_info.get('country', 'Unknown')
    region_response = ip_info.get('region', 'Unknown')
    city_response = ip_info.get('city', 'Unknown')
    
    connection_info_response = ip_info.get('connection', {})
    isp_response = connection_info_response.get('isp', 'Unknown')
    org_response = connection_info_response.get('org', 'Unknown')

    lat_response = ip_info.get('latitude', 'Unknown')
    lon_response = ip_info.get('longitude', 'Unknown')

    print(f"""
[+] Target IP: {ip_response}
[+] Country: {country_response}
[+] Region: {region_response}
[+] City: {city_response}
[+] ISP: {isp_response}
[+] ORG: {org_response}
[+] Coordinates: {lat_response}, {lon_response}""")

    if is_datacenter_isp(isp_response, blacklist):
        print("\n[!] WARNING: Datacenter or Cloud provider detected (Possible VPN/Proxy)")

    print("-" * 50)

def execute_ip_lookup(ip_target="", blacklist=None, verbose=False, api_engine='ipwhois'):
    raw_result = get_ip_info(ip_target, api_engine)

    if raw_result is not None:
        if verbose:
            print(f"\n[DEBUG] Raw API Response ({api_engine}):\n{json.dumps(raw_result, indent=2)}")
    
        # Pass the raw data through the Adapter
        normalized_result = normalize_api_response(raw_result, api_engine)

        if normalized_result.get(API_SUCCESS_KEY):
            print_info(normalized_result, blacklist)
        else:
            print(f"[!] Target IP {ip_target} not found or invalid via {api_engine}.")
    else:
        print(f"[!] Empty Information for IP: {ip_target if ip_target else 'Local'}")

def process_file(file_path, blacklist=None, verbose=False):
    print(f"[*] Reading IP file: {file_path}")
    processed = 0
    skipped = 0

    try:
        with open(file_path, 'r') as file:

            for line in file:
                target_ip = line.strip()

                if not target_ip or target_ip.startswith('#'):
                    continue

                print(f"\n--- Researching: {target_ip} ---")

                if is_valid_public_ip(target_ip):
                    execute_ip_lookup(target_ip, blacklist, verbose)
                    processed += 1
                    time.sleep(RATE_LIMIT_DELAY)
                else:
                    skipped += 1

        total = processed + skipped
        print(f"\n[+] Done -- Processed: {processed} | Skipped: {skipped} | Total: {total}")

    except FileNotFoundError:
        print(f"[!] Error: The file was not found: '{file_path}'")

def load_custom_blacklist(file_path):
    custom_list = []
    try:
        with open(file_path, 'r') as file:
            for line in file:
                keyword = line.strip().lower()
                if keyword:
                    custom_list.append(keyword)
        print(f"[*] Loaded custom blacklist with {len(custom_list)} keywords.")
        return custom_list
    except FileNotFoundError:
        print(f"[!] Error: Custom blacklist file '{file_path}' not found. Using default list")
        return None

if __name__ == "__main__":
    # Parser Definition
    parser = argparse.ArgumentParser(description="IP Tracker OSINT Tool")
    parser.add_argument('-i', '--input_ip', type=str, help='Specific input IP')
    parser.add_argument('-f', '--file', type=str, help='IP file to process')
    parser.add_argument('-b', '--blacklist', type=str, help='Custom ISP blacklist file (.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output (print raw API JSON)')
    parser.add_argument('--api', type=str, choices=['ipwhois', 'ipapi'], default='ipwhois', help='Select the API engine (default: ipwhois with TLS)')

    # Read user args
    args = parser.parse_args()

    # API Security Check
    if args.api == 'ipapi':
        print("\n[!] WARNING: You selected the 'ipapi' engine which uses unencrypted HTTP.")
        print("Your traffic (including the IPs you track) could be intercepted (MITM).")
        consent = input("Do you want to proceed without TLS? [y/N]: ").strip().lower()
        if consent != 'y':
            print("[*] Operation cancelled by the user. Enforcing secure defaults.")
            sys.exit(0)
    
    # Load Custom Blacklist
    active_blacklist = DEFAULT_BLACKLIST
    if args.blacklist:
        loaded_list = load_custom_blacklist(args.blacklist)
        if loaded_list is not None:
            active_blacklist = loaded_list

    # Routing
    if args.file:
        process_file(args.file, active_blacklist, args.verbose, args.api)

    elif args.input_ip:
        if not is_valid_public_ip(args.input_ip):
            sys.exit(1)

        execute_ip_lookup(args.input_ip, active_blacklist, args.verbose, args.api)

    else:
        print("\n[!] WARNING: You are about to query your local machine's public IP.")
        print("This will expose your IP to a third-party API (ipwho.is).")
        consent = input("Do you want to proceed? [y/N]: ").strip().lower()

        if consent == 'y':
            execute_ip_lookup("", active_blacklist, args.verbose, args.api)
        else:
            print("[*] Operation cancelled by the user. Stay safe.")
            sys.exit(0)
