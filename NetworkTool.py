"""This code provides some network and cybersecurity features"""
# Date : 19/09/2024
# Author : xKayniT
# Description : Network tool with many options related to cybersecurity

import hashlib
import pathlib
import re
import json
import subprocess
import requests
from scapy.all import *

def display():
    """This function is here to display a menu for user."""
    print("Welcome to Network Tool Analyzer. This tool is developed by xKayniT using scapy library and differents API endpoints.")
    print("Please choose an options below :")
    print("1. Ping")
    print("2. Traceroute(with geographical view of IP address)")
    print("3. Check SSL certificate of a website")
    print("4. Sniffing packets")
    print("5. Hash file analysis")
    options_number = str(input(""))
    match options_number :
        case "1":
            ping()
        case "2":
            traceroute_func()
        case "3":
            ssl_informations()
        case "4":
            sniffing_packets()
        case "5":
            hash_analysis()
        case _:
            print("Option not available yet")

# This function is defined to ping an IP address
def ping():
    """This function is defined to ping an IP address with scapy package"""
    print("--Ping option--")
    chosen_ip_addr = str(input("Choose the targeted IP address : "))
    ping_packet = IP(dst=chosen_ip_addr,ttl=64)/ICMP()
    reply_packet = sr1(ping_packet,timeout=10)
    if reply_packet:
        print(reply_packet, "is online")
    else:
        raise ValueError(f"Timeout(10 secondes) waiting for {chosen_ip_addr}")

# This function is defined to use traceroute command with geographical view
def traceroute_func():
    """This function is defined to use traceroute command with geographical view."""
    print("--Traceroute option--")
    chosen_domain = str(input("Choose the targeted website : "))
    conf.geoip_city = "databases/GeoLite2-City.mmdb"
    try:
        traceroute_map([chosen_domain])
    except:
        raise ValueError("Error in loading maps")

# The purpose of this function is to call ssl-checker.io API to retrieve informations from the website certificate
def ssl_informations():
    """The purpose of this function is to call ssl-checker.io API to retrieve informations from the website certificate."""
    print("--SSL checker option--")
    chosen_website = str(input("Choose the targeted website : "))
    cmd = "curl https://ssl-checker.io/api/v1/check/" + chosen_website
    # Execute the command
    returned_value = subprocess.run(cmd, shell=True, capture_output=True, text=True, check=False)
    # print('result', returned_value)
    if returned_value:
        try:
            # Display info with indentation
            json_data = json.loads(returned_value.stdout)
            formatted_json = json.dumps(json_data, indent=4)
            print(formatted_json)
        except:
            raise Exception("JSOn data can't be displayed")

# The purpose of this function is to give to the user a mean to sniff packets
def sniffing_packets():
    """The purpose of this function is to give to the user a mean to sniff packets."""
    print("--Sniffing packets option--")
    sniffing_packets_number = int(input("Which number of packets do you want sniff : "))
    filter_protocol = str(input("Filter protocol : "))
    try:
        packets_sniffing = sniff(filter=filter_protocol, count=sniffing_packets_number)
        packets_sniffing.summary()
    except:
        raise Exception("Sniffing options have failed")

# The purpose of this function is to give to the user a feedback about a given hash calculated from a file or hash(virustotal and kaspersky endpoint)
def hash_analysis():
    """The purpose of this function is to give to the user a feedback about a given hash calculated from a file or hash(virustotal and kaspersky endpoint)."""
    print("--Hash analysis option--")
    targeted_file_hash = str(input("Indicate the full path of the targeted file or a hash : "))
    try:
        # Check if the given string is a hash, else calculate it from a file
        if re.search(r"^[A-Za-z0-9]{32}$", targeted_file_hash):
            # Send the request to virustotal API
            url = "https://www.virustotal.com/api/v3/files/" + targeted_file_hash
            headers = {
                "accept": "application/json",
                "x-apikey": "YOUR-API-KEY"
            }
            response = requests.get(url, headers=headers,timeout=10)
            # Transform received data
            data = response.json()
            print(json.dumps(data, indent=4))
        else:
            md5_hash_file = hashlib.md5(pathlib.Path(targeted_file_hash).read_bytes()).hexdigest()
            # Send the request to virustotal API
            url = "https://www.virustotal.com/api/v3/files/" + md5_hash_file
            headers = {
                "accept": "application/json",
                "x-apikey": "YOUR-API-KEY"
            }
            response = requests.get(url, headers=headers, timeout=10)
            # Transform received data
            data = response.json()
            print(json.dumps(data, indent=4))
    except:
        raise Exception("Error in hash calculation")

display()
