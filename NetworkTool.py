# Date : 19/09/2024
# Author : xKayniT
# Description : Network tool with many options related to cybersecurity

from scapy.all import *
from subprocess import run
import json
from iptools import *
from requests import post
import hashlib
import pathlib
import requests
import re

def display():
    print("Welcome to Network Tool Analyzer. This tool is developed by xKayniT using scapy library and differents API endpoints.")
    print("Please choose an options below :")
    print("1. Ping")
    print("2. Traceroute(with geographical view of IP address)")
    print("3. Check SSL certificate of a website")
    print("4. Sniffing packets")
    print("5. Hash file analysis")
    options_number = str(input(""))
    if options_number == "1":
        ping()
    elif options_number == "2":
        traceroute_func()
    elif options_number == "3":
        ssl_informations()
    elif options_number == "4":
        sniffing_packets()
    elif options_number == "5":
        hash_analysis()
    else:
        print("Option not available yet")

# This function is defined to ping an IP address
def ping():
    print("--Ping option--")
    chosen_IP_addr = str(input("Choose the targeted IP address : "))
    ping_packet = IP(dst=chosen_IP_addr,ttl=64)/ICMP()
    reply_packet = sr1(ping_packet,timeout=10)
    if reply_packet:
        print(reply_packet, "is online")
    else:
        print("Timeout(10 secondes) waiting for %s" % chosen_IP_addr)

# This function is defined to use traceroute command wth geographical view
def traceroute_func():
    print("--Traceroute option--")
    chosen_domain = str(input("Choose the targeted website : "))
    conf.geoip_city = "databases/GeoLite2-City.mmdb"
    try:
        traceroute_map([chosen_domain])
    except:
        print("Error in loading maps")

# The purpose of this function is to call ssl-checker.io API to retrieve informations from the website certificate
def ssl_informations():
    print("--SSL checker option--")
    chosen_website = str(input("Choose the targeted website : "))
    cmd = "curl https://ssl-checker.io/api/v1/check/" + chosen_website
    # Execute the command
    returned_value = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    # print('result', returned_value)
    if returned_value:
        try:
            # Display info with indentation
            json_data = json.loads(returned_value.stdout)
            formatted_json = json.dumps(json_data, indent=4)
            print(formatted_json)
        except:
            print("JSOn data can't be displayed")

# The purpose of this function is to give to the user a mean to sniff packets
def sniffing_packets():
    print("--Sniffing packets option--")
    sniffing_packets_number = int(input("Which number of packets do you want sniff : "))
    filter_protocol = str(input("Filter protocol : "))
    try:
        packets_sniffing = sniff(filter=filter_protocol, count=sniffing_packets_number)
        packets_sniffing.summary()
    except:
        print("Sniffing options have failed")

# The purpose of this function is to give to the user a feedback about a given hash calculated from a file or hash(virustotal and kaspersky endpoint)
def hash_analysis():
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
            response = requests.get(url, headers=headers)
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
            response = requests.get(url, headers=headers)
            # Transform received data
            data = response.json()
            print(json.dumps(data, indent=4))
    except:
        print("Error in hash calculation")

display()