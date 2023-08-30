# Scapy

from scapy.all import *
import sys

conf.verb = 0


def load_ports_from_file(filename):
    port_file = open(filename)
    ports = port_file.read().split(",")
    return [int(port) for port in ports]


def is_ping_reply(ping):
    return ping[1][ICMP].type == 0


def is_tcp_synack(packet):
    return packet[1][TCP].flags == "SA"


packet = send(IP(src="10.255.255.10") / ICMP())
print(packet)

if len(sys.argv) != 2:
    print("Skrypt przyjmuje 2 argumenty.")
    print(f"python3 {sys.argv[0]} <adres sieci lub hosta>")

target = sys.argv[1]

print("[+] Stage: Service discovery")
pings, unans = sr(IP(dst=target) / ICMP(), timeout=2)

hosts = []
for ping in pings:
    if ping[1][ICMP].type != 0:
        continue
    hosts.apped({
        "ip": ping[0].dst,
        "services": []
    })

print("[+] Stage: Service discovery")

for host in hosts:
    tcp_results, unans = sr(IP(dst=host["ip"]) / TCP(dport=[80, 443]), timeout=1)
    print(f'Host {host["ip"]}')
    for tcp_conn in tcp_results:
        print(tcp_conn)  # dla każdego połączenia TCP wypisuje wynik połączenia
        flags = tcp_conn[1][TCP].flags  # tcp_conn[0] = query, tcp_conn[1] = answer
        print(tcp_conn[0][TCP].dport)  # informacja, który port był skanowany
        if flags != "SA":  # SA = SYN ACK
            continue  # pomijamy nieudane połączenia
        # if is_tcp_synack(tcp_conn) == False znaczy to samo co powyższy
        hosts["services"].append(tcp_conn[0][TCP].dport)
        print(f"\t- Open port: {tcp_conn[0][TCP].dport}")
