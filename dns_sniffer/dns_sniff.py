#! /usr/bin/python

from scapy.all import *
import sys
import os
from colorama import Fore
from datetime import datetime



try:
    interface = input("[?] Interface: ")
    print("[!] Listening...")
except KeyboardInterrupt:
    print("[!] User Requested Shutdown...")
    print("\n[!] Exiting...")
    sys.exit(1)

def querysniff(pkt):
    patterns = {
        "tiktok": "[i] User opened tiktok",
        "instagram": "[i] User opened instagram",
        "twitter": "[i] User opened twitter",
        "contacts.icloud.com": "[i] User opened the contacts app",
        "guzzoni": "[i] User opened/closed their phone"
    }

    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        last = ""
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and str(pkt.getlayer(DNS).qd.qname) != last:
            now = datetime.now()
            time_str = now.strftime("%H:%M:%S")

            qname = str(pkt.getlayer(DNS).qd.qname)
            for webSite, action in patterns.items():
                if webSite in qname:
                    print("[", time_str, "]", Fore.GREEN, action)
                    break  # Exit the loop after the first match
            print("[",time_str,"]", str(ip_src) , " -> " , str(ip_dst) , " : " , "(" + str(pkt.getlayer(DNS).qd.qname) , ")")
            last = str(pkt.getlayer(DNS).qd.qname)

sniff(iface = interface,filter = "port 53", prn = querysniff, store = 0)
print("\n[!] Shutting Down...")
