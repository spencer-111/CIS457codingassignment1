from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET, timeout

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"  # ICANN Root Server
DNS_PORT = 53


def get_dns_record(udp_socket, domain: str, parent_server: str, record_type):
    q = DNSRecord.question(domain, qtype=record_type)
    q.header.rd = 0  # Recursion Desired?  NO
    # print("DNS query", repr(q))
    udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
    pkt, _ = udp_socket.recvfrom(8192)
    buff = DNSBuffer(pkt)

    answers_list = []
    cname = ""
    ns_list = []
    add_list = []

    header = DNSHeader.parse(buff)
    # print("DNS header", repr(header))
    if q.header.id != header.id:
        return {
            "answers": [],
            "cname": "",
            "ns": [],
            "additional": [],
            "error": "Unmatched transaction"
        }
    if header.rcode == RCODE.NXDOMAIN:
        return {
            "answers": [],
            "cname": "",
            "ns": [],
            "additional": [],
            "error": "Nonexistent domain"
        }
    if header.rcode != RCODE.NOERROR:
        return {
            "answers": [],
            "cname": "",
            "ns": [],
            "additional": [],
            "error": "Query Failed"
        }

    # Parse the question section #2
    for k in range(header.q):
        DNSQuestion.parse(buff)

    # Parse the answer section #3
    for k in range(header.a):
        a = RR.parse(buff)
        if a.rtype == QTYPE.CNAME:
            cname = str(a.rdata)
        if a.rtype == QTYPE.A:
            answers_list.append(str(a.rdata))

    # Parse the authority section #4
    for k in range(header.auth):
        auth = RR.parse(buff)
        if auth.rtype == QTYPE.NS:
            ns_list.append(str(auth.rdata))

    # Parse the additional section #5
    for k in range(header.ar):
        adr = RR.parse(buff)
        if adr.rtype == QTYPE.A:
            add_list.append(str(adr.rdata))

    return {
        "answers": answers_list,
        "cname": cname,
        "ns": ns_list,
        "additional": add_list,
        "error": None
    }


def create_labels(dm):
    if dm[-1] == '.':
        dm = dm[0:-1]
    labels = []
    parts = dm.split('.')
    labels.append(parts[-1])
    labels.append(parts[-2] + '.' + parts[-1])
    labels.append(dm + '.')
    for label in labels:
        if not label:
            return IndexError
    return labels


def resolve(s, domain, servers, rtype="NS") -> dict:
    nonexistent = False

    for server in servers:
        try:
            r = get_dns_record(s, domain, server, rtype)
        except timeout:
            continue
        if r["error"] is not None:
            if r["error"] == "Nonexistent domain":
                nonexistent = True
            continue

        if r["answers"]:
            return {
                "answers": r["answers"],
                "cname": r["cname"] if r["cname"] else None,
                "error": None
            }

        if r["cname"]:
            print(f"cname of {domain} is {r['cname']}")
            return {
                "answers": [],
                "cname": r["cname"],
                "error": None
            }

        if r["ns"]:
            ns_ips = []
            if r["additional"]:
                ns_ips.extend(r["additional"])

            if not ns_ips:
                for ns_host in r["ns"]:
                    ns_resp = resolve(s, ns_host, resolve_tld(s, ns_host))
                    if ns_resp["answers"]:
                        ns_ips.extend(ns_resp["answers"])

            if ns_ips:
                return {
                    "answers": ns_ips,
                    "cname": None,
                    "error": None
                }
        print("Nonexistent domain")
        continue
    if nonexistent:
        return {
            "answers": [],
            "cname": None,
            "error": "Nonexistent domain"
        }
    else:
        return {
            "answers": [],
            "cname": None,
            "error": "Could not find address"
        }


def resolve_tld(s, d):
    n = get_dns_record(s, d, ROOT_SERVER, "NS")
    return n["additional"]


if __name__ == '__main__':
    if __name__ == '__main__':
        sock = socket(AF_INET, SOCK_DGRAM)
        sock.settimeout(2)
        cache = dict()

        while True:
            domain_name = input("Enter a domain name or .exit > ")

            if domain_name == '.exit':
                break

            if domain_name == '.list':
                items = list(cache.items())
                for i in range(len(items)):
                    print(f'{i + 1}. {items[i][0]}: {items[i][1]}')
                    i += 1
                continue

            if domain_name == '.clear':
                cache.clear()
                continue

            remove_args = domain_name.split()
            if remove_args and remove_args[0] == '.remove':
                if not remove_args[1].isnumeric():
                    print(".remove arg has to be a number")
                    continue
                if int(remove_args[1]) <= 0:
                    print(".remove arg must be positive")
                    continue
                if int(remove_args[1]) > len(cache):
                    print(f".remove arg must less than number of cache entries {(len(cache))}")
                    continue
                names = list(cache.keys())
                cache.pop(names[int(remove_args[1]) - 1])
                continue

            try:
                d_labels = create_labels(domain_name)
            except IndexError:
                print("Nonexistent domain")
                continue

            while True:
                d_labels = create_labels(domain_name)
                ips = None
                auth_servers = None
                tld_servers = None

                # check cache
                if cache.get(d_labels[2], None):
                    print(f"IP address resolution of \"{d_labels[2][0:-1]}\" found in cache")
                    ips = cache[d_labels[2]]
                elif cache.get(d_labels[1], None):
                    print(f"Authoritative servers of \"{d_labels[1]}\" found in cache")
                    auth_servers = cache[d_labels[1]]
                elif cache.get(d_labels[0], None):
                    print(f"TLD servers of \"{d_labels[0]}\" found in cache")
                    tld_servers = cache[d_labels[0]]

                if not ips and not auth_servers and not tld_servers:
                    resolve_r = resolve(sock, d_labels[0], [ROOT_SERVER])
                    if resolve_r["cname"] is not None:
                        domain_name = resolve_r["cname"]
                        continue
                    if resolve_r["error"] is not None:
                        print(resolve_r["error"])
                        break

                    tld_servers = resolve_r["answers"]
                    print(f"TLD servers of \"{d_labels[0]}\" found from root")
                    cache.update({d_labels[0]: tld_servers})

                if not ips and not auth_servers:
                    resolve_r = resolve(sock, d_labels[1], tld_servers)
                    if resolve_r["cname"] is not None:
                        domain_name = resolve_r["cname"]
                        continue
                    if resolve_r["error"] is not None:
                        print(resolve_r["error"])
                        break

                    auth_servers = resolve_r["answers"]
                    print(f"Authoritative server of \"{d_labels[1]}\" found from TLD server")
                    cache.update({d_labels[1]: auth_servers})

                if not ips:
                    resolve_r = resolve(sock, d_labels[2], auth_servers, "A")
                    if resolve_r["cname"] is not None:
                        domain_name = resolve_r["cname"]
                        continue
                    if resolve_r["error"] is not None:
                        print(resolve_r["error"])
                        break

                    ips = resolve_r["answers"]
                    print(f"IP address resolution of \"{d_labels[2]}\" found from authoritative server")
                    cache.update({d_labels[2]: ips})

                print(repr(ips))
                break

        sock.close()
