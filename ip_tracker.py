#!/usr/bin/env python3
import urllib.request
import json
import sys
import ipaddress
import argparse

DEFAULT_BLACKLIST = ['amazon', 'aws', 'digitalocean', 'linode', 'hetzner', 
    'ovh', 'tor', 'cloudflare', 'google', 'vultr', 'choopa', 
    'microsoft', 'azure', 'alibaba', 'tencent', 'hosting', 'datacenter']
 
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


def get_ip_info(ip_adress=""):
    # The public API we are using
    url = f"http://ip-api.com/json/{ip_adress}"
    print(f"[*] Establishing connection to {url}...")

    try:
        response = urllib.request.urlopen(url)
        raw_data = response.read().decode('utf-8')
        return json.loads(raw_data)

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return None

def print_info(ip_info, blacklist=None):

    if blacklist is None:
        blacklist = DEFAULT_BLACKLIST

    query_response = ip_info.get('query', 'N/A')
    country_response = ip_info.get('country', 'Unknown')
    city_response = ip_info.get('city', 'Unknown')
    isp_response = ip_info.get('isp', 'Unknown')

    print(f"""
[+] Target IP: {query_response}
[+] Country: {country_response}
[+] City: {city_response}
[+] ISP: {isp_response}
""")

    isp_lower = isp_response.lower()

    if any(keyword in isp_lower for keyword in blacklist):
        print("     [!] WARNING: Datacenter or Cloud provider detected (Possible VPN/Proxy)")

    print("-" * 50)

def execute_ip_lookup(ip_target="", blacklist=None):
    result = get_ip_info(ip_target)
    if result is not None and result.get('status') == 'success':
        print_info(result, blacklist)
    else:
        print(f"[!] Empty Information for IP: {ip_target if ip_target else 'Local'}")

def process_file(file_path, blacklist=None):
    print(f"[*] Reading IP file: {file_path}")
    try:
        with open(file_path, 'r') as file:

            for line in file:
                target_ip = line.strip()

                if not target_ip:
                    continue

                print(f"\n--- Researching: {target_ip} ---")

                if is_valid_public_ip(target_ip):
                    execute_ip_lookup(target_ip, blacklist)

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

    # Read user args
    args = parser.parse_args()

    # Load Custom Blacklist
    active_blacklist = None
    if args.blacklist:
        active_blacklist = load_custom_blacklist(args.blacklist)

    # Routing
    if args.file:
        process_file(args.file, active_blacklist)

    elif args.input_ip:
        if not is_valid_public_ip(args.input_ip):
            sys.exit(1)

        execute_ip_lookup(args.input_ip, active_blacklist)

    else:
        execute_ip_lookup("", active_blacklist)
