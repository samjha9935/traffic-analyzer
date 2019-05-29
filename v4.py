#Import Modules
import threading
import time
from scapy.all import *
import logging
from datetime import datetime
#Function Definitions

#2 S
#16 A
#18 SA
#17 FA
#24 PA
#20 RA
#36 UA

ACK_L = []
PUSHACK_L = []
FINACK_L = []
RSTACK_L = []
SYN_L = []
SYNACK_L = []


def logfun():
	threading.Timer(20.0,logfun).start()
	logging.basicConfig(filename='loginfo.log', level=logging.DEBUG)
	logging.info('%s : PACKETS: %d %d %d',str(datetime.now()),len(SYN_L),len(SYNACK_L),len(ACK_L))
	logging.warning('%s : Protocol Problem',str(datetime.now()))


def checkack():
	threading.Timer(6.0,checkack).start()
	flag = 0
	for pa in ACK_L:
		for psa in SYNACK_L:
			if pa.ack == psa.seq+1:
				if pa.sport == psa.dport and pa.dport == psa.sport and pa[IP].src == psa[IP].dst and pa[IP].dst == psa[IP].src:
					for ps in SYN_L:
						if psa.ack == ps.seq+1:
							if ps.sport == psa.dport and ps.dport == psa.sport and ps[IP].src == psa[IP].dst and ps[IP].dst == psa[IP].src:
								wrpcap('match.pcap',ps,append=True)
								wrpcap('match.pcap',psa,append=True)
								wrpcap('match.pcap',pa,append=True)
								#del(ps)
								flag=1
								break
			if flag==1:
				del(psa)
				flag=0
				break
	ACK_L[:] = []
def checkfack():
	threading.Timer(6.0,checkfack).start()
	flag=0
	for pa in FINACK_L:
		for psa in SYNACK_L:
			if pa.ack == psa.seq+1:
				if pa.sport == psa.dport and pa.dport == psa.sport and pa[IP].src == psa[IP].dst and pa[IP].dst == psa[IP].src:
					for ps in SYN_L:
						if psa.ack == ps.seq+1:
							if ps.sport == psa.dport and ps.dport == psa.sport and ps[IP].src == psa[IP].dst and ps[IP].dst == psa[IP].src:
								wrpcap('match.pcap',ps,append=True)
								wrpcap('match.pcap',psa,append=True)
								wrpcap('match.pcap',pa,append=True)
								del(ps)
								flag=1
								break
			if flag==1:
				del(psa)
				flag=0
				break
	FINACK_L[:] = []
def checkrstack():
	threading.Timer(6.0,checkrstack).start
	flag=0
	for pa in RSTACK_L:
		for psa in SYNACK_L:
			if pa.ack == psa.seq+1:
				if pa.sport == psa.dport and pa.dport == psa.sport and pa[IP].src == psa[IP].dst and pa[IP].dst == psa[IP].src:
					for ps in SYN_L:
						if psa.ack == ps.seq+1:
							if ps.sport == psa.dport and ps.dport == psa.sport and ps[IP].src == psa[IP].dst and ps[IP].dst == psa[IP].src:
								wrpcap('match.pcap',ps,append=True)
								wrpcap('match.pcap',psa,append=True)
								wrpcap('match.pcap',pa,append=True)
								del(ps)
								flag=1
								break
			if flag==1:
				del(psa)
				flag=0
				break
	RSTACK_L[:] = []
def checkpack():
	threading.Timer(6.0,checkpack).start()
	flag = 0
	for pa in PUSHACK_L:
		for psa in SYNACK_L:
			if pa.ack == psa.seq+1:
				if pa.sport == psa.dport and pa.dport == psa.sport and pa[IP].src == psa[IP].dst and pa[IP].dst == psa[IP].src:
					for ps in SYN_L:
						if psa.ack == ps.seq+1:
							if ps.sport == psa.dport and ps.dport == psa.sport and ps[IP].src == psa[IP].dst and ps[IP].dst == psa[IP].src:
								wrpcap('match.pcap',ps,append=True)
								wrpcap('match.pcap',psa,append=True)
								wrpcap('match.pcap',pa,append=True)
								del(ps)
								flag=1
								break
			if flag==1:
				del(psa)
				flag=0
				break
	PUSHACK_L[:] = []
def delpkt():
	threading.Timer(4.0, delpkt).start()
	i = 0
	j = 0
	while i<len(SYN_L):
		if(time.time()-SYN_L[i][TCP].time)/60000>0.6:
			SYN_L.pop(i)
		i=i+1
	while j<len(SYNACK_L):
		if(time.time()-SYNACK_L[j][TCP].time)/60000>0.6:
			SYNACK_L.pop(j)
		j=j+1

def append_list(pkt):
#WITH VALIDATION
	if pkt[TCP].flags == 16 and pkt[TCP].ack and pkt[TCP].sport and pkt[TCP].dport:
		ACK_L.append(pkt)
	elif pkt[TCP].flags == 2 and pkt[TCP].seq and pkt[TCP].sport and pkt[TCP].dport:
		SYN_L.append(pkt)
	elif pkt[TCP].flags == 18 and pkt[TCP].ack and pkt[TCP].seq and pkt[TCP].sport and pkt[TCP].dport:
		SYNACK_L.append(pkt)
	elif pkt[TCP].flags == 17 and pkt[TCP].ack and pkt[TCP].sport and pkt[TCP].dport:
		FINACK_L.append(pkt)
	elif pkt[TCP].flags == 20 and pkt[TCP].ack and pkt[TCP].sport and pkt[TCP].dport:
		RSTACK_L.append(pkt)
	elif pkt[TCP].flags == 24 and pkt[TCP].ack and pkt[TCP].sport and pkt[TCP].dport:
		PUSHACK_L.append(pkt)
#DRIVER
sniff(iface='enp2s0', filter = 'tcp', store = 0, count = 100, prn = append_list)
logfun()
checkack()
checkfack()
checkpack()
checkrstack()
delpkt()
sniff(iface='enp2s0', filter = 'tcp', store = 0, prn = append_list)
