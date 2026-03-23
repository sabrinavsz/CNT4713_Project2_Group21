import sys
import socket
import struct
import random


def build_dns_query(domain_name):
    # build the dns header for one standard query
    transaction_id = random.randint(0, 65535)
    flags = 0
    question_count = 1
    answer_count = 0
    authority_count = 0
    additional_count = 0

    header = struct.pack(
        "!HHHHHH",
        transaction_id,
        flags,
        question_count,
        answer_count,
        authority_count,
        additional_count
    )

    # build the qname by turning each label into
    # length byte + label bytes, then end with 0
    qname = b""
    for label in domain_name.split("."):
        qname += struct.pack("!B", len(label))
        qname += label.encode()

    qname += b"\x00"

    # qtype 1 = a record
    # qclass 1 = internet
    question = qname + struct.pack("!HH", 1, 1)

    return header + question


def read_dns_name(packet, offset):
    # read a domain name from the packet
    # handle both normal labels and compressed pointers
    labels = []
    jumped = False
    next_offset = offset

    while True:
        length = packet[offset]

        # check if this is a compressed pointer
        if (length & 0xC0) == 0xC0:
            pointer = struct.unpack("!H", packet[offset:offset + 2])[0] & 0x3FFF

            if not jumped:
                next_offset = offset + 2

            offset = pointer
            jumped = True

        elif length == 0:
            if not jumped:
                next_offset = offset + 1
            break

        else:
            offset += 1
            label = packet[offset:offset + length].decode()
            labels.append(label)
            offset += length

            if not jumped:
                next_offset = offset

    return ".".join(labels), next_offset


def parse_resource_record(packet, offset):
    # read the name field first
    name, offset = read_dns_name(packet, offset)

    # read the fixed resource record fields
    record_type, record_class, ttl, rdlength = struct.unpack(
        "!HHIH",
        packet[offset:offset + 10]
    )
    offset += 10

    rdata_offset = offset
    offset += rdlength

    record = {
        "name": name,
        "type_code": record_type,
        "class": record_class,
        "ttl": ttl,
        "rdlength": rdlength
    }

    # handle only the record types we need for the project
    if record_type == 1 and rdlength == 4:
        # a record
        ip_address = ".".join(str(byte) for byte in packet[rdata_offset:rdata_offset + 4])
        record["type"] = "A"
        record["value"] = ip_address

    elif record_type == 2:
        # ns record
        ns_name, _ = read_dns_name(packet, rdata_offset)
        record["type"] = "NS"
        record["value"] = ns_name

    else:
        # store unsupported types in a simple readable way
        record["type"] = f"TYPE_{record_type}"
        record["value"] = packet[rdata_offset:rdata_offset + rdlength]

    return record, offset


def parse_dns_response(packet):
    # read the dns header counts
    header = struct.unpack("!HHHHHH", packet[:12])
    transaction_id, flags, question_count, answer_count, authority_count, additional_count = header

    offset = 12

    # skip over the question section
    for _ in range(question_count):
        _, offset = read_dns_name(packet, offset)
        offset += 4

    answer_records = []
    authority_records = []
    additional_records = []

    # parse answer records
    for _ in range(answer_count):
        record, offset = parse_resource_record(packet, offset)
        answer_records.append(record)

    # parse authority records
    for _ in range(authority_count):
        record, offset = parse_resource_record(packet, offset)
        authority_records.append(record)

    # parse additional records
    for _ in range(additional_count):
        record, offset = parse_resource_record(packet, offset)
        additional_records.append(record)

    return {
        "transaction_id": transaction_id,
        "flags": flags,
        "question_count": question_count,
        "answer_count": answer_count,
        "authority_count": authority_count,
        "additional_count": additional_count,
        "answers": answer_records,
        "authority": authority_records,
        "additional": additional_records
    }


def print_dns_response(dns_server_ip, parsed_response):
    print("--------------------------------------------------")
    print(f"DNS server to query: {dns_server_ip}")
    print("Reply received. Content overview:\n")

    print(f"{parsed_response['answer_count']} Answers.")
    print(f"{parsed_response['authority_count']} Intermediate Name Servers.")
    print(f"{parsed_response['additional_count']} Additional Information Records.\n")

    print("Answers section:")
    for record in parsed_response["answers"]:
        if record["type"] == "A":
            print(f"    Name: {record['name']:<25} IP: {record['value']}")
        elif record["type"] == "NS":
            print(f"    Name: {record['name']:<25} Name Server: {record['value']}")

    print("Authority Section:")
    for record in parsed_response["authority"]:
        if record["type"] == "NS":
            print(f"    Name: {record['name']:<25} Name Server: {record['value']}")
        elif record["type"] == "A":
            print(f"    Name: {record['name']:<25} IP: {record['value']}")

    print("Additional Information Section:")
    for record in parsed_response["additional"]:
        if record["type"] == "A":
            print(f"    Name: {record['name']:<25} IP: {record['value']}")
        elif record["type"] == "NS":
            print(f"    Name: {record['name']:<25} Name Server: {record['value']}")

    print()


def choose_next_dns_server_ip(authority_records, additional_records):
    # collect the ns host names listed in the authority section
    authority_name_servers = set()

    for record in authority_records:
        if record["type"] == "NS":
            authority_name_servers.add(record["value"])

    # find an a record in additional that matches one of those ns names
    for record in additional_records:
        if record["type"] == "A" and record["name"] in authority_name_servers:
            return record["value"]

    return None


def send_query(server_ip, query_packet):
    # send the raw udp query packet to port 53 and wait for the reply
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.settimeout(5)

    try:
        client_socket.sendto(query_packet, (server_ip, 53))
        response_packet, _ = client_socket.recvfrom(4096)
        return response_packet
    finally:
        client_socket.close()


def extract_final_ips(answer_records, target_domain):
    # collect final a record answers that match the domain we asked for
    final_ips = []

    for record in answer_records:
        if record["type"] == "A":
            if record["name"].rstrip(".").lower() == target_domain.rstrip(".").lower():
                final_ips.append(record["value"])

    return final_ips


def main():
    if len(sys.argv) != 3:
        print("usage: python mydns.py <domain-name> <root-dns-ip>")
        sys.exit(1)

    target_domain = sys.argv[1].strip()
    current_dns_server_ip = sys.argv[2].strip()

    visited_servers = set()

    while True:
        if current_dns_server_ip in visited_servers:
            print("stopped because the lookup started looping between servers")
            break

        visited_servers.add(current_dns_server_ip)

        try:
            query_packet = build_dns_query(target_domain)
            response_packet = send_query(current_dns_server_ip, query_packet)
            parsed_response = parse_dns_response(response_packet)

            print_dns_response(current_dns_server_ip, parsed_response)

            final_ips = extract_final_ips(parsed_response["answers"], target_domain)

            # if we found the final a record answers, print them and stop
            if final_ips:
                print("Final IP address(es):")
                for ip_address in final_ips:
                    print(ip_address)
                break

            # otherwise choose one intermediate dns server and continue
            next_dns_server_ip = choose_next_dns_server_ip(
                parsed_response["authority"],
                parsed_response["additional"]
            )

            if next_dns_server_ip is None:
                print("could not find the next dns server ip from the authority/additional sections")
                break

            current_dns_server_ip = next_dns_server_ip

        except socket.timeout:
            print(f"timeout while querying dns server {current_dns_server_ip}")
            break

        except Exception as error:
            print(f"error: {error}")
            break


if __name__ == "__main__":
    main()