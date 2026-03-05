#!/usr/bin/env python3
import urllib.request
import json
import sys
import ipaddress

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
        json_data = json.loads(raw_data)

        return json_data

    except Exception as e:
        print(f"[!] Connection error: {e}")
        return None

def print_info(ip_info):
    query_response = ip_info['query'] 
    country_response = ip_info['country']
    city_response = ip_info['city']
    isp_response = ip_info['isp']
    print(f"""
[+] Target IP: {query_response}
[+] Country: {country_response}
[+] City: {city_response}
[+] ISP: {isp_response}
""")

if __name__ == "__main__":
    result = ""
    if len(sys.argv) > 1:
        if not is_valid_public_ip(sys.argv[1]): 
            sys.exit(1)
        result = get_ip_info(sys.argv[1])
    else:
        result = get_ip_info()
    if result is not None and result.get('status') == 'success':
        print_info(result)
    else:
        print("[!] Empty Information")
