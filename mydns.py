import socket
import sys
import random
import struct

# Creates query to be sent

def buildDNS(domain):
    transactionID = random.randint(0,65535) # min to max value for transaction IDs
    flags = 0x0100 # DNS query
    qdcount = 1 # 1 query

    header = struct.pack(">HHHHHH", transactionID, flags, qdcount, 0, 0, 0) # ID number, query type. # of questions, and servers

    parts = domain.split(".") # divides domain name and type
    qname = b""

    for part in parts:
        qname += struct.pack("B", len(part))
        qname += part.encode()
    qname += b"\x00"
    # Translates domain into DNS

    question = qname + struct.pack(">HH", 1, 1) # 1 = IP, 1 = Internet

    return header + question

# Check for arguments
if len(sys.argv) != 3:
    print("Usage: python mydns.py domain root_dns_ip")
    sys.exit(1) 

domain = sys.argv[1]
root_IP = sys.argv[2] # Creates domain to test DNS request

# Socket Programming to send query and receive a reply from root DNS server

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # AF_INET is Internet Protocol Version 4, SOCK_DGRAM is UDP
sock.settimeout(5) # Stops waiting for a response after 5 seconds
packet = buildDNS(domain) # Creates packet

sock.sendto(packet, (root_IP, 53)) # Send request to including DNS packet, server being sent to, and DNS port

data, _ = sock.recvfrom(512) # Awaits response and receives up to 512 bytes, the standard size for DNS; returns data and address

print(f"Sending query to {root_IP}...")
print("Reply Received.")
print(f"Bytes Received:  {len(data)}") # Confirmation statements

sock.close() # Closes socket