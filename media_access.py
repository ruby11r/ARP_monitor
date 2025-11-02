#!usr/bin/env python

import scapy.all as scapy

# This module contains MAC class which can scan the network and find the MAC address for an IP address
# Tested against Python v2 and v3
# Last update: 2 Nov 2025


class MediaAccessControl:
    def __init__(self, ip, name):
        self.ip = ip
        self.name = name
        self.broadcast = 'ff:ff:ff:ff:ff:ff'
        self.interface = 'eth0' # static value for a local network

    def __repr__(self):
        return self.name + ': ' + self.ip

    def find_mac_by_ip(self):
        # Create an ARP packet for specific ip address
        arp_req = scapy.ARP(pdst=self.ip)
        # custom ether layer of broadcast packet providing a destination address
        broadcast = scapy.Ether(dst=self.broadcast)
        # the combined packet
        arp_broadcast = broadcast / arp_req
        # Send the packet will receive a list of response with answered and unanswered lists
        try:
            element = scapy.srp(arp_broadcast, timeout=3, verbose=False)[0][0][1]
            # check the information
            # print(f'{element.hwsrc} type {type(element.hwsrc)}')
            return element.hwsrc
        except Exception as e:
            print('>>> DEBUG: Error while retrieving MAC address: ' + str(e))
            return None

