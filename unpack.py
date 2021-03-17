#!/usr/bin/env python3
# -*- coding:utf-8 -*-

import socket
import struct

def unpack_mac(data):
    d = data
    d = '%.2X-%.2X-%.2X-%.2X-%.2X-%.2X'%(d[0],d[1],d[2],d[3],d[4],d[5])
    return d

def unpack_eth(data):
    e = data
    eth = struct.unpack('!6s6sH',e)
    des_mac = unpack_mac(eth[0])
    sour_mac = unpack_mac(eth[1])
    eth_type = socket.ntohs(eth[2])
    eth_res = {'Destination MAC':des_mac,
            'Source MAC':sour_mac,
            'Ethernet type':eth_type
            }
    return eth_res

def unpack_ip(data):
    i = data
    ip = struct.unpack('!BBHHHBBH4s4s',i)
    print(ip)
    version0 = ip[0]
    version = version0 >> 4
    ipl_l = version0 & 0xf
    ipl = ipl_l*4
    total_len = ip[2]
    identi = ip[3]
    flags = ip[4]
    ttl = ip[5]
    protocol = ip[6]
    h_check = ip[7]
    s_ip = socket.inet_ntoa(ip[8])
    d_ip = socket.inet_ntoa(ip[9])
    ip_res = {'IP Version':version,
            'Header length':ipl,
            'Total length':total_len,
            'Identification':identi,
            'Flags':flags,
            'Time to live':ttl,
            'Protocol':protocol,
            'Header checksum':h_check,
            'Source IP Address':s_ip,
            'Destination IP Address':d_ip
            }
    return ip_res

def unpack_tcp(data):
    t = data
    tcp = struct.unpack('!HHLLBBHHH',t)
    s_port = tcp[0]
    d_port = tcp[1]
    s_num = tcp[2]
    a_num = tcp[3]
    header_len = tcp[4]
    flags = tcp[5]
    w_size = tcp[6]
    checksum = tcp[7]
    u_pointer = tcp[8]
    tcp_res = {'Source Port':s_port,
            'Destination Port':d_port,
            'Sequence Number':s_num,
            'Acknowledgment Number':a_num,
            'Header Length':header_len,
            'Flags':flags,
            'Window Size':w_size,
            'Checksum':checksum,
            'Urgent pointer':u_pointer
            }
    return tcp_res

def unpack_udp(data):
    u = data
    udp = struct.unpack('!HHHH',u)
    s_port = udp[0]
    d_port = udp[1]
    udp_len = udp[2]
    checksum = udp[3]
    udp_res = {'Source Port':s_port,
            'Destination Port':d_port,
            'UDP Length':udp_len,
            'Checksum':checksum
            }
    return udp_res

def unpack_icmp(data):
    i = data
    icmp = struct.unpack('!BBH',i)
    i_type = icmp[0]
    i_code = icmp[1]
    i_checksum = icmp[2]
    icmp_res = {'ICMP Type':i_type,
            'ICMP Code':i_code,
            'ICMP Checksum':i_checksum
            }
    return icmp_res

