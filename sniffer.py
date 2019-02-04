import socket
import os
import struct
import binascii

def analyze_udp_header(data):
    udp_hdr  	 = struct.unpack("!4H",data[:8])
    src_port 	 = udp_hdr[0]
    dst_port 	 = udp_hdr[1]
    length   	 = udp_hdr[2]
    chk_sum  	 = udp_hdr[3]
    data         = data[8:]
    print "---------UDP HEADER INFORMATION------------"
    print "Source port: "+str(src_port)
    print "Destination port: "+str(dst_port)
    print "Length: "+str(length)
    print "Checksum: "+str(chk_sum)
    return data

def analyze_tcp_header(data):
    tcp_hdr  	 = struct.unpack("!2H2I4H",data[:20])
    src_port 	 = tcp_hdr[0]
    dst_port 	 = tcp_hdr[1]
    seq_num  	 = tcp_hdr[2]
    ack_num  	 = tcp_hdr[3]
    data_offset	 = tcp_hdr[4] >> 12
    reserved 	 = (tcp_hdr[4] >> 6) & 0x03ff
    flags        = tcp_hdr[4] & 0x003f
    urg          = flags & 0x0020
    urg          = urg >> 5
    ack		 = flags & 0x0010
    ack          = ack >> 4
    psh          = flags & 0x0008
    psh		 = psh >> 3
    rst	         = flags & 0x0004
    rst		 = rst >> 2
    syn	         = flags & 0x0002
    syn	         = syn >> 1
    fin          = flags & 0x0001
    window       = tcp_hdr[5]
    checksum 	 = tcp_hdr[6]
    urg_ptr      = tcp_hdr[7]
    data         = data[20:]
    print "-------------------TCP HEADER INFORMATION-----------------------"
    print "Source Port: "+str(src_port)
    print "Destination Port: "+str(dst_port)
    print "Sequence Number: "+str(seq_num)
    print "Acknowledgment Number: "+str(ack_num)
    print "Data Offset: "+str(data_offset)
    print "URG Pointer: "+str(urg_ptr)
    print "Checksum: "+str(checksum)
    print "Window: "+str(window)
    print "--Flag Values--"
    print "URG : "+str(urg)
    print "Ack : "+str(ack)
    print "Psh: "+str(psh)
    print "Rst: "+str(rst)
    print "Syn: "+str(syn)
    print "Fin: "+str(fin)
    return data

def analyze_ip_header(data):
    ip_hdr 	     = struct.unpack("!6H4s4s",data[:20])
    ver	 	     = ip_hdr[0] >> 12
    ihl	 	     = (ip_hdr[0] >>8 ) & 0x0f
    tos	 	     = ip_hdr[0] & 0x00ff
    tot_len	     = ip_hdr[1]
    ip_id	     = ip_hdr[2]
    flags	     = ip_hdr[3] >> 13
    flag_offset	     = ip_hdr[3] & 0x1fff
    ip_ttl	     = ip_hdr[4] >> 8
    ip_proto 	     = ip_hdr[4] & 0x00ff
    chk_sum	     = ip_hdr[5]
    src_addr	     = socket.inet_ntoa(ip_hdr[6])
    des_addr         = socket.inet_ntoa(ip_hdr[7])

    if ip_proto == 6:
        next_proto = "TCP"
  #  elif ip_proto== 17 :
  #      next_proto = "UDP"
    else:
        next_proto = "Other"

    data=data[20:]
    print "IP Version: "+str(ver)
    print "Internet Header Length: "+str(ihl)
    print "Type of Service: "+str(tos)
    print "Total Length: "+str(tot_len)
    print "Identification: "+str(ip_id)
    print "Protocol: "+str(next_proto)
    print "Checksum: "+str(chk_sum)
    print "Source address: "+str(src_addr)
    print "Destination address: "+str(des_addr)
    return data , next_proto

def analyze_ether_header(data):
    print "\n\n\n\n"
    ip_bool      = False
    eth_hdr      = struct.unpack("!6s6sH",data[:14])
    dest_mac	 = binascii.hexlify(eth_hdr[0])
    src_mac	     = binascii.hexlify(eth_hdr[1])
    proto	     = eth_hdr[2]
    print "destination mac address is "+dest_mac[0:2]+":"+dest_mac[2:4]+":"+dest_mac[4:6]+":"+dest_mac[6:8]+":"+dest_mac[8:10]+":"+dest_mac[10:12]
    print "Source mac address is "+src_mac[0:2]+":"+src_mac[2:4]+":"+src_mac[4:6]+":"+src_mac[6:8]+":"+src_mac[8:10]+":"+src_mac[10:12]

    if str(hex(proto))== "0x800":
        ip_bool=True
    data=data[14:]
    return data , ip_bool

def main():
    sniffer_socket= socket.socket(socket.PF_PACKET, socket.SOCK_RAW , socket.htons(0x0003))
    recv_data 	  = sniffer_socket.recv(2048)
    data, ip_bool = analyze_ether_header(recv_data)
    next_proto=-1
    if ip_bool:
        data,next_proto = analyze_ip_header(data)

    if next_proto == "TCP":
        data = analyze_tcp_header(data)
    elif next_proto =="UDP":
        data = analyze_udp_header(data)
    else:
        return
while True:
    main()
