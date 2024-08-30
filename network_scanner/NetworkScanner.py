# By: THE WHACK HACK

# !/usr/bin/env python
import optparse
import scapy.all as scapy

parser = optparse.OptionParser()
parser.add_option("-v", "--verbose", action="store_true", default=False, dest="verbose",
                  help="verbose")  # Creates Options
parser.add_option("--ip", action="store", type="str", dest="ip")
(options, arguments) = parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)  # pdst == ip feild.
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Ether == MAC Field
    arp_append = broadcast / arp_request  # "/" appends in scapy
    answered_list = scapy.srp(arp_append, timeout=1, verbose=options.verbose)[0]  # Verbose in input,False by default.

    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}  # [1] is the reply.
        clients_list.append(client_dict)
    return clients_list


def print_result(results_list):
    print("ip\t\t\tMAC Address\n---------------------------------------------------------")  # \t == tab
    for client in results_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan(options.ip)
print_result(scan_result)
