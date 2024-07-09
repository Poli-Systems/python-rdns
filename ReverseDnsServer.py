# Created by Philippe Raimundo from Poli Systems GmbH
# 2024 Poli Systems GmbH

from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, AAAA, SOA, NS, CAA
from dnslib.server import DNSServer, BaseResolver
import re
import datetime
import time
import os

# Variables for the domain and IP addresses
DOMAIN = 'polisystems.cloud'

# SOA record details
SOA_REFRESH = 3600  # Refresh interval in seconds
SOA_RETRY = 1800  # Retry interval in seconds
SOA_EXPIRE = 1209600  # Expire interval in seconds
SOA_MINIMUM = 86400  # Minimum TTL in seconds

# NS record details

# Default TTL for all records (7 days in seconds)
TTL = 604800

# CAA record details
CAA_FLAGS = 0
CAA_TAG = 'issue'
CAA_VALUE = 'letsencrypt.org'

# Path to the stats file
STATS_FILE = '/root/DNS/stats.txt'

# Global counter for DNS queries
dns_query_counter = 0

# Function to load the current count from the stats file
def load_stats():
    global dns_query_counter
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE, 'r') as f:
            try:
                dns_query_counter = int(f.read().strip().split(': ')[1])
            except (IndexError, ValueError):
                dns_query_counter = 0
    else:
        dns_query_counter = 0

# Function to update the stats.txt file
def update_stats():
    with open(STATS_FILE, 'w') as f:
        f.write(f"DNS Queries: {dns_query_counter}\n")

# Function to generate a new serial number based on the current date and time
def generate_serial():
    now = datetime.datetime.now()
    return int(now.strftime('%Y%m%d%H%M%S'))  # YYYYMMDDHHMMSS format

class CustomResolver(BaseResolver):
    def resolve(self, request, handler):
        global dns_query_counter
        dns_query_counter += 1
        update_stats()

        reply = request.reply()
        qname = request.q.qname
        qtype = QTYPE[request.q.qtype]
        domain = str(qname).strip('.').lower()  # Normalize the domain to lower case

        print(f"Request for domain: {domain} of type: {qtype}")

        # Update the SOA serial number to the current date and time
        SOA_SERIAL = generate_serial()

        # Adjusted regex patterns to handle any subdomain and suffix after the target domain
        direct_match = re.match(r'^(.*\.)?(\d+)\.(\d+)\.(\d+)\.(\d+)\.' + re.escape(DOMAIN) + '$', domain)
        reverse_match = re.match(r'^(.*\.)?(\d+)\.(\d+)\.(\d+)\.(\d+)\.reverse\.' + re.escape(DOMAIN) + '$', domain)

        if direct_match:
            ip_address = ".".join(direct_match.groups()[-4:])
            print(f"Direct match found: {ip_address}")
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_address), ttl=TTL))
        elif reverse_match:
            ip_address = ".".join(reverse_match.groups()[-4:][::-1])
            print(f"Reverse match found: {ip_address}")
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip_address), ttl=TTL))
        elif domain == DOMAIN:
            print(f"Root domain query for {DOMAIN}")
            if qtype == 'A':
                reply.add_answer(RR(qname, QTYPE.A, rdata=A(IPV4_ADDRESS), ttl=TTL))
            elif qtype == 'AAAA':
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(IPV6_ADDRESS), ttl=TTL))
            elif qtype == 'SOA':
                soa_record = SOA(mname=SOA_MNAME,
                                 rname=SOA_RNAME,
                                 times=(SOA_SERIAL, SOA_REFRESH, SOA_RETRY, SOA_EXPIRE, SOA_MINIMUM))
                reply.add_answer(RR(qname, QTYPE.SOA, rdata=soa_record, ttl=TTL))
            elif qtype == 'NS':
                for ns in NS_SERVERS:
                    reply.add_answer(RR(qname, QTYPE.NS, rdata=NS(ns), ttl=TTL))
            elif qtype == 'CAA':
                caa_record = CAA(flags=CAA_FLAGS, tag=CAA_TAG, value=CAA_VALUE)
                reply.add_answer(RR(qname, QTYPE.CAA, rdata=caa_record, ttl=TTL))
            else:
                print(f"Unhandled query type: {qtype}")
        else:
            print("No match found")

        return reply

if __name__ == '__main__':
    load_stats()  # Load the current count when the script starts
    resolver = CustomResolver()
    server = DNSServer(resolver, port=53, address='0.0.0.0')
    server.start_thread()

    try:
        while True:
            time.sleep(0.1)  # Add a sleep interval to reduce CPU usage
    except KeyboardInterrupt:
        pass