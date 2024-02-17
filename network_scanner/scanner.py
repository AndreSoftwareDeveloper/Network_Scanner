from scapy.all import *
from scapy.layers.inet import ICMP, IP, TCP

conf.verb = 0


########################################
# TODO:
# Możliwość spoofowania adresu MAC i IP
# Możliwość zmiany źródłowego portu TCP
########################################

def load_ports_from_file(filename):
    ports_file = open(filename)
    ports = ports_file.read().split(",")
    return [int(port) for port in ports]


def is_ping_reply(ping):
    return ping[1][ICMP].type == 0


def is_tcp_synack(packet):
    return packet[1][TCP].flags == "SA"


if len(sys.argv) != 2:
    print(f"python3 {sys.argv[0]} <host or network address>")

target = sys.argv[0]
pings, unans = sr(IP(dst=target) / ICMP(), timeout=2)

hosts = []
for ping in pings:
    if not is_ping_reply(ping):
        continue
    hosts.append({
        "ip": ping[0].dst,
        "services": []
    })

print("[+] Stage: Services discovery")
nmap_top1000_int = load_ports_from_file("../../nmap-top1000.txt")

for host in hosts:
    tcp_results, unans = sr(IP(dst=host["ip"] / TCP(dport=nmap_top1000_int), timeout=1))
    print(f'Host: {host["ip"]}')

    for tcp_conn in tcp_results:
        if not is_tcp_synack(tcp_conn):
            continue
        host["services"].append(tcp_conn[0][TCP].dport)
        print(f"\t- Open port: {tcp_conn[0][TCP].dport}")
