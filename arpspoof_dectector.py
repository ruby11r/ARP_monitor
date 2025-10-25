#!usr/bin/env python
from scapy.all import Ether, ARP, srp, sendp, sniff
import time

# THIS program test against Python2 and Python3 on Kail Linux and Windows10.
# Program requires another machine running and may run arp_spoof.py
# Updated 5 Oct 2025

GATEWAY_IP = '192.168.150.2'  # Gateway IP of the router
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

def sniff_pkt(iface):
    try:
        # Run for specific duration
        sniff(iface=iface, store=False, prn=process_sniffed_pkt, timeout=60)
    except Exception as e:
        print('>>> DEBUG: Error while sniffing packets.' + str(e))


def process_sniffed_pkt(packet):
    print('>> INFO: Program running...')
    if packet.haslayer(ARP) and packet[ARP].op == 2:
        print('>> INFO: ARP exist in the packet, checking in progress....')
        # print(packet.show())
        test = is_arp_compromised(packet)
        if test: # true
            print('>> WARNING: ARP spoof in progress..This machine is under attack.')
        elif test == False:
            print('>> INFO: ARP table in order.')
        else:
            print('>> DEBUG: Unable to test the system now.. try again later.')
    else:
        print('>> INFO: No ARP layer detected in the packet...')

    time.sleep(5)



def find_mac_by_ip(ip):
    # This program requires another machine(s) running
    # Create an ARP packet for specific ip address
    arp_req = ARP(pdst=ip)
    # custom ether layer of broadcast packet providing a destination address
    broadcast = Ether(dst=BROADCAST_MAC)
    # combined packet
    arp_broadcast = broadcast / arp_req
    # Send the packet will receive a list of responses with answered and unanswered lists
    try:
        element = srp(arp_broadcast, timeout=3, verbose=False)[0][0][1]
        # print(f'{element.hwsrc} type {type(element.hwsrc)}')
        return element.hwsrc
    except Exception as e:
        print('>>> ERROR: problem with retrieving MAC address: ' + str(e))
    return None


def is_arp_compromised(packet):
    # Checking the MAC's sender is not the gateway False for compromised case, None for unknown
    real_gateway_mac = find_mac_by_ip(packet[ARP].psrc) # get the MAC of gateway
    # Get ARP sender mac
    if real_gateway_mac:
        if real_gateway_mac != packet[ARP].hwsrc:
            return True
        else:
            return False
    return None # something went wrong, such as MAC address retrival



def main():
    iface = 'eth0'
    sniff_pkt(iface)


main()

