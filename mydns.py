#!/usr/bin/env python3

import socket
import struct
import random
import sys

DNS_PORT = 53
TIMEOUT_SECONDS = 5
MAX_ITERATIONS = 20

TYPE_A = 1
TYPE_NS = 2
CLASS_IN = 1

# Converts a normal domain name into DNS wire format
def encodeDomainName(domain):
    parts = domain.strip(".").split(".")
    encoded = b""
    for part in parts:
        encoded += struct.pack("!B", len(part))
        encoded += part.encode("ascii")
    encoded += b"\x00"
    return encoded

# Builds the full DNS query packet, including the header and question section
def buildDnsQuery(domain):
    transaction_id = random.randint(0, 65535)
    flags = 0x0000
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack("!HHHHHH",
                         transaction_id,
                         flags,
                         qdcount,
                         ancount,
                         nscount,
                         arcount)

    question = encodeDomainName(domain)
    question += struct.pack("!HH", TYPE_A, CLASS_IN)

    return transaction_id, header + question

# Reads a domain name from a DNS message and handles compressed names if needed
def readName(message, offset):
    labels = []
    jumped = False
    original_offset = offset

    while True:
        length = message[offset]

        if length == 0:
            offset += 1
            break

        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", message[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                original_offset = offset + 2
            offset = pointer
            jumped = True
            continue

        offset += 1
        labels.append(message[offset:offset + length].decode("ascii"))
        offset += length

    name = ".".join(labels)
    return name, (original_offset if jumped else offset)

# Skips over the question section so parsing can continue into the reply records
def parseQuestionSec(message, offset, qdcount):
    for _ in range(qdcount):
        _, offset = readName(message, offset)
        offset += 4
    return offset

# Parses one resource record section such as Answers, Authority, or Additional
def parseRRSec(message, offset, count):
    records = []

    for _ in range(count):
        name, offset = readName(message, offset)

        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10

        rdata_offset = offset
        rdata = message[offset:offset + rdlength]

        record = {
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata_raw": rdata,
            "data": None
        }

        if rtype == TYPE_A and rdlength == 4:
            record["data"] = socket.inet_ntoa(rdata)

        elif rtype == TYPE_NS:
            ns_name, _ = readName(message, rdata_offset)
            record["data"] = ns_name

        records.append(record)
        offset += rdlength

    return records, offset

# Parses the full DNS server reply
def parseDnsR(message):
    if len(message) < 12:
        raise ValueError("Invalid DNS message: too short")

    transaction_id, flags, qdcount, ancount, nscount, arcount = struct.unpack(
        "!HHHHHH", message[:12]
    )

    qr = (flags >> 15) & 0x1
    rcode = flags & 0xF

    offset = 12
    offset = parseQuestionSec(message, offset, qdcount)

    answers, offset = parseRRSec(message, offset, ancount)
    authorities, offset = parseRRSec(message, offset, nscount)
    additionals, offset = parseRRSec(message, offset, arcount)

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "qr": qr,
        "rcode": rcode,
        "qdcount": qdcount,
        "ancount": ancount,
        "nscount": nscount,
        "arcount": arcount,
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals
    }

# Sends a DNS query to the given server and returns the parsed reply
def sendDnsQ(server_ip, domain):
    txid, query = buildDnsQuery(domain)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_SECONDS)

    try:
        sock.sendto(query, (server_ip, DNS_PORT))
        response, _ = sock.recvfrom(4096)
        parsed = parseDnsR(response)

        if parsed["transaction_id"] != txid:
            raise ValueError("Transaction ID mismatch")

        return parsed
    finally:
        sock.close()

# Displays the reply content 
def printRes(server_ip, response):
    print("----------------------------------------------------------------")
    print(f"DNS server to query: {server_ip}")
    print("Reply received. Content overview:")
    print(f"{len(response['answers'])} Answers.")
    print(f"{len(response['authorities'])} Intermediate Name Servers.")
    print(f"{len(response['additionals'])} Additional Information Records.")

    print("Answers section:")
    for rr in response["answers"]:
        if rr["type"] == TYPE_A:
            print(f"Name : {rr['name']} IP : {rr['data']}")

    print("Authority Section:")
    for rr in response["authorities"]:
        if rr["type"] == TYPE_NS:
            print(f"Name : {rr['name']} Name Server: {rr['data']}")

    print("Additional Information Section:")
    for rr in response["additionals"]:
        if rr["type"] == TYPE_A:
            print(f"Name : {rr['name']} IP : {rr['data']}")

# Pulls out the final IPv4 answers from the Answers section
def getAnswerIps(response):
    ips = []
    for rr in response["answers"]:
        if rr["type"] == TYPE_A and rr["data"] is not None:
            ips.append(rr["data"])
    return ips

# Finds the next DNS server IP by matching Authority NS records with Additional A records
def chooseNextServiceIp(response):
    additional_a_records = {}
    for rr in response["additionals"]:
        if rr["type"] == TYPE_A and rr["data"] is not None:
            additional_a_records[rr["name"].lower()] = rr["data"]

    for rr in response["authorities"]:
        if rr["type"] == TYPE_NS and rr["data"] is not None:
            ns_name = rr["data"].lower()
            if ns_name in additional_a_records:
                return additional_a_records[ns_name]

    return None

# Controls the full iterative lookup process from the root server to the final answer
def iterativeDnsLookup(domain, root_dns_ip):
    current_server = root_dns_ip

    for _ in range(MAX_ITERATIONS):
        response = sendDnsQ(current_server, domain)
        printRes(current_server, response)

        if response["rcode"] != 0:
            print(f"DNS error: server returned RCODE {response['rcode']}")
            return

        answer_ips = getAnswerIps(response)
        if answer_ips:
            print("----------------------------------------------------------------")
            print(f"Final IP(s) for {domain}:")
            for ip in answer_ips:
                print(ip)
            return

        next_server = chooseNextServiceIp(response)
        if next_server is None:
            print("----------------------------------------------------------------")
            print("Could not find an intermediate DNS server IP in the Additional section.")
            return

        current_server = next_server

    print("----------------------------------------------------------------")
    print("Maximum iterative lookup depth reached.")

# Checks whether the root DNS server input is a valid IPv4 address
def validateIpv4(ip):
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False


def main():
    if len(sys.argv) != 3:
        print("Usage: python mydns.py domain-name root-dns-ip")
        sys.exit(1)

    domain = sys.argv[1].strip()
    root_dns_ip = sys.argv[2].strip()

    if not domain:
        print("Error: domain name cannot be empty.")
        sys.exit(1)

    if not validateIpv4(root_dns_ip):
        print("Error: invalid root DNS IPv4 address.")
        sys.exit(1)

    try:
        iterativeDnsLookup(domain, root_dns_ip)
    except socket.timeout:
        print("Error: DNS query timed out.")
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()