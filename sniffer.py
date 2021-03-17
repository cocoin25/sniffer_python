#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import socket
from struct import *
from unpack import *
s = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(0x800))

while True:
    r = s.recvfrom(65565)
    res = r[0]
    e = res[0:14]
    eth = unpack_eth(e)
    print('\n\n---------------Ethernet------------\n')
    for k,v in eth.items():
        print ('{} : {} | '.format(k,v),end='')

    i = res[14:34]
    ip = unpack_ip(i)
    print('\n\n---------------Internet Protocol---------\n')
    for k,v in ip.items():
        print('{} : {} | '.format(k,v),end='')
    if ip['Protocol'] ==6:
        t = res[34:54]
        tcp = unpack_tcp(t)
        print('\n\n--------------TCP----------------\n')
        for k,v in tcp.items():
            print('{} : {} | '.format(k,v),end='')
    elif ip['Protocol'] == 17:
        u = res[34:42]
        udp = unpack_udp(u)
        print('\n\n---------------UDP----------\n')
        for k,v in udp.items():
            print('{} : {} | '.format(k,v),end='')
    elif ip['Protocol'] == 1:
        i = res[34:37]
        icmp = unpack_icmp(i)
        print('\n\n-------------ICMP-----------\n')
        for k,v in icmp.items():
            print('{} : {} | '.format(k,v))


