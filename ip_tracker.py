#!/usr/bin/env python3
import urllib.request
import json
import sys
import ipaddress
import argparse

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

def print_info(ip_info):
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

def execute_ip_lookup(ip_target=""):
    result = get_ip_info(ip_target)
    if result is not None and result.get('status') == 'success':
        print_info(result)
    else:
        print(f"[!] Empty Information for IP: {ip_target if ip_target else 'Local'}")

def process_file(file_path):
    print(f"[*] Reading IP file: {file_path}")
    try:
        with open(file_path, 'r') as file:

            for line in file:
                target_ip = line.strip()

                if not target_ip:
                    continue

                print(f"\n--- Researching: {target_ip} ---")

                if is_valid_public_ip(target_ip):
                    execute_ip_lookup(target_ip)

    except FileNotFoundError:
        print(f"[!] Error: The file was not found: '{file_path}'")

if __name__ == "__main__":
    # Parser Definition
    parser = argparse.ArgumentParser(description="IP Tracker OSINT Tool")
    parser.add_argument('-i', '--input_ip', type=str, help='Specific input IP')
    parser.add_argument('-f', '--file', type=str, help='IP file to process')

    # Read user args
    args = parser.parse_args()

    # Routing
    if args.file:
        process_file(args.file)

    elif args.input_ip:
        if not is_valid_public_ip(args.input_ip):
            sys.exit(1)

        execute_ip_lookup(args.input_ip)

    else:
        execute_ip_lookup()
