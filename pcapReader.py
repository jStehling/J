from ftplib import print_line
from sys import flags

from scapy.all import *
import csv

from scapy.layers.dns import DNS, DNSQR, DNSRR


#file is where data will be written to
#pcapfile is the pcap file it will read from
def wriet(file, pcapfile):
    metadata = ["timestamp","flag", "source", "destination", "qname", "ttl"]

    packets = rdpcap(pcapfile)

    with open(file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(metadata)

        for pkt in packets:
            currentPacket = []
            if pkt.haslayer(DNS):
                flag = pkt[DNS].qr
                pktime = int(pkt.time)
                strTime = datetime.fromtimestamp(pktime).strftime('%Y-%m-%d %H:%M:%S')
                packetTime = strTime[11:]
                currentPacket.append(packetTime)
                currentPacket.append(flag)
                currentPacket.append(pkt[IP].src)
                currentPacket.append(pkt[IP].dst)
                currentPacket.append(pkt[DNS].qd.qname.decode("utf-8"))
                #flag of 1 means a response from server and not 2 means it cant be a server failiure
                if flag == 1:
                    if pkt.haslayer(DNSRR):
                        currentPacket.append(pkt[DNSRR].ttl)
                    else:
                        if pkt[DNS].ancount > 0 or pkt[DNS].nscount > 0:
                            currentPacket.append(pkt[DNS].ns.ttl)
                writer.writerow(currentPacket)


#and pkt[DNS].rcode != 2
# code above was to check for server failure
#originally needed it to work, machine decided it didnt need it anymore

wriet()


