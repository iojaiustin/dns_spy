#! /usr/bin/python

from scapy.all import *
import sys
import os
from colorama import Fore
from datetime import datetime



try:
    interface = input("[?] Interface")
except KeyboardInterrupt:
    print("[!] User Requested Shutdown...")
    print("[!] Exiting...")
    sys.exit(1)

def querysniff(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        last = ""
        if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0 and str(pkt.getlayer(DNS).qd.qname) != last:
            now = datetime.now()
            time_str = now.strftime("%H:%M:%S")

            if "tiktok" in str(pkt.getlayer(DNS).qd.qname):
                print("[",time_str,"]", Fore.GREEN,"[i] User opened tiktok")
            if "instagram" in str(pkt.getlayer(DNS).qd.qname):
                print("[",time_str,"]", Fore.GREEN,"[i] User opened instagram")
            if "twitter" in str(pkt.getlayer(DNS).qd.qname):
                print("[",time_str,"]", Fore.GREEN,"[i] User opened twitter")
            if "contacts.icloud.com" in str(pkt.getlayer(DNS).qd.qname):
                print("[",time_str,"]", Fore.GREEN,"[i] User opened the contacts app")
            if "guzzoni" in str(pkt.getlayer(DNS).qd.qname):
            	print("[",time_str,"]", Fore.GREEN,"[i] User opened/closed their phone")

            print("[",time_str,"]", str(ip_src) , " -> " , str(ip_dst) , " : " , "(" + str(pkt.getlayer(DNS).qd.qname) , ")")
            last = str(pkt.getlayer(DNS).qd.qname)

sniff(iface = interface,filter = "port 53", prn = querysniff, store = 0)
print("\n[!] Shutting Down...")
