#!/usr/bin/python
# IPv6 packet generator
# Created by Rich Compton 
# This script generates IPv6 packets
# This may not make enough DDoS traffic to bring down a network, you may want to capture this traffic with "tcpdump -w <filename> port <udp port>" and then replay them with "tcpreplay -i <interface> -tKq --loop=0 <filename>"
# This should be run as root

import argparse, os, sys, random
from scapy.all import *

if not os.geteuid() == 0:
    sys.exit('Script must be run as root.')


# Make scapy be quiet and not print dots when sending a packet
conf.verb=0

# Get arguments on the command line
parser = argparse.ArgumentParser(description='This script will generate IPv6 pakcets similar to hping3.')

parser.add_argument('-m','--dstmac', help='Specify a destination MAC (ip -6 neigh)', required=True)
parser.add_argument('-r','--srcmac', help='Specify a source MAC (ip -6)', required=False, default='fe:ed:de:ad:be:ef')
parser.add_argument('-d','--destination', help='Specify a destination IP or subnet',required=True)
parser.add_argument('-a','--spoof', help='Use  this  option  in  order to set a fake IP source address',required=False)
parser.add_argument('-p','--destport', help='Specify a destination port.  If unspecified, it will be random.',required=False)
parser.add_argument('-s','--sourceport', help='Specify a source port.  If unspecified, it will be random.',required=False)
parser.add_argument('-l','--length', help='Specify a length of the payload in bytes.  If unspecified, it will be random.',required=False)
parser.add_argument('-c','--count', help='Specify number of packets to generate.  If unspecified, it will be 1.',required=False, type=int, default=1)
parser.add_argument('-t','--hoplimit', help='Specify the hop limit (TTL) of the packet.  If unspecified, it will be 255.',required=False, type=int, default=255)
parser.add_argument('-i','--interface', help='Specify an interface to use for sending the packets',required=False)
parser.add_argument('--protocol', help='Specify a L4 protocol (udp|tcp).  If unspecified, it will be UDP.',required=False, default='udp')
args = parser.parse_args()


# If the payload is greater than 1452, set it to 1452
if int(args.length) > 1452:
    print(f'Payload length {args.length} is greater than the max of 1452.  Setting payload to 1452')
    args.length = 1452


# If the hop limit is greater than 255
if int(args.hoplimit) > 255:
    print(f'Hop limit {args.hoplimit} is greater than the max of 255.  Setting hopt limti to 255')
    args.hoplimit = 255

# Create the counter
x = 0

# Keep generating packets until we have reached the number specified
while x < int(args.count):

    if args.spoof is None:
        # Create a random source IPv6 address
        M = 16**4
        src = "2001:dead:" + ":".join(("%x" % random.randint(0, M) for i in range(6)))

    else:
        src = args.spoof

    if args.destport is None:
        # Create random destination port
        dport = random.randint(1024, 65535)
    
    else:
        dport = int(args.destport)

    # If source port is 0 then we generate a random port number
    if args.sourceport is None:
        sport = random.randint(1024, 65535)

    else:
        sport = int(args.sourceport)

    # If packet length is 0 then we generate a random packet lenght
    if args.length is None:
        length = random.randint(0, 1450)
    else:
        length = int(args.length)

    # Set the payload
    payload = "\x00"*(length)

    #Create either UDP or TCP packet
    if args.protocol == "udp":
        p1=Ether(src=args.srcmac, dst=args.dstmac)/IPv6(dst=args.destination,src=src,hlim=args.hoplimit)/UDP(dport=dport,sport=sport)/payload
    else:
        p1=Ether(src=args.srcmac, dst=args.dstmac)/IPv6(dst=args.destination,src=src,hlim=args.hoplimit)/TCP(dport=dport,sport=sport)/payload
    
    # Send packet
    sendp(p1, iface=args.interface)

    #Increment the counter    
    x = x + 1
