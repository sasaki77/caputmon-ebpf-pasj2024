#!/usr/bin/python

from bcc import BPF
from sys import argv

import socket
import os

from pprint import pprint

CA_COMMANDS = {
    0: "CA_PROTO_VERSION",
    4: "CA_PROTO_WRITE",
    12: "CA_PROTO_CLEAR_CHANNEL",
    15: "CA_PROTO_READ_NOTIFY",
    18: "CA_PROTO_CREATE_CHAN",
    20: "CA_PROTO_CLIENT_NAME",
    21: "CA_PROTO_HOST_NAME",
    22: "CA_PROTO_ACCESS_RIGHTS",
}


# args
def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()


# help
def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    exit()


def toIPstr(ba: bytearray):
    ip = ""
    for i, b in enumerate(ba):
        ip += str(int(b))
        if i < 3:
            ip += "."
    return ip


# arguments
interface = "eth0"

if len(argv) == 2:
    if str(argv[1]) == "-h":
        help()
    else:
        usage()

if len(argv) == 3:
    if str(argv[1]) == "-i":
        interface = argv[2]
    else:
        usage()

if len(argv) > 3:
    usage()

print("binding socket to '%s'" % interface)

# initialize BPF - load source code from http-parse-simple.c
print("load eBPF program")
bpf = BPF(src_file="caputmon.c", debug=0)

# load eBPF program ca_filter of type SOCKET_FILTER into the kernel eBPF vm
function_http_filter = bpf.load_func("ca_filter", BPF.SOCKET_FILTER)

# create raw socket, bind it to interface
# attach bpf program to socket created
BPF.attach_raw_socket(function_http_filter, interface)

# get file descriptor of the socket previously created inside BPF.attach_raw_socket
socket_fd = function_http_filter.sock

# create python socket object, from the file descriptor
sock = socket.fromfd(socket_fd, socket.PF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)
# set it as blocking socket
sock.setblocking(True)

request_pv_table = {}
connected_pv_table = {}

print("start")
while 1:
    # retrieve raw packet from socket
    packet_str = os.read(socket_fd, 2048)

    # DEBUG - print raw packet in hex format
    # packet_hex = toHex(packet_str)
    # print ("%s" % packet_hex)

    # convert packet into bytearray
    packet_bytearray = bytearray(packet_str)

    # ethernet header length
    ETH_HLEN = 14

    # parse mac address
    dst_mac = packet_bytearray[0:6]
    src_mac = packet_bytearray[6:12]

    # IP HEADER
    # calculate packet total length
    total_length = packet_bytearray[ETH_HLEN + 2]  # load MSB
    total_length = total_length << 8  # shift MSB
    total_length = total_length + packet_bytearray[ETH_HLEN + 3]  # add LSB

    # calculate ip header length
    ip_header_length = packet_bytearray[ETH_HLEN]  # load Byte
    ip_header_length = ip_header_length & 0x0F  # mask bits 0..3
    ip_header_length = ip_header_length << 2  # shift to obtain length

    # parse IP info
    proto = packet_bytearray[ETH_HLEN + 9]
    src_ip = packet_bytearray[ETH_HLEN + 12 : ETH_HLEN + 16]
    dst_ip = packet_bytearray[ETH_HLEN + 16 : ETH_HLEN + 20]

    # TCP HEADER
    tcp_offset = ETH_HLEN + ip_header_length

    # calculate tcp header length
    tcp_header_length = packet_bytearray[ETH_HLEN + ip_header_length + 12]  # load Byte
    tcp_header_length = tcp_header_length & 0xF0  # mask bit 4..7
    tcp_header_length = tcp_header_length >> 2  # SHR 4 ; SHL 2 -> SHR 2

    # parse TCP info
    src_port = int.from_bytes(packet_bytearray[tcp_offset : tcp_offset + 2], "big")
    dst_port = int.from_bytes(packet_bytearray[tcp_offset + 2 : tcp_offset + 4], "big")

    # calculate payload offset
    payload_offset = ETH_HLEN + ip_header_length + tcp_header_length

    src_ip_str = toIPstr(src_ip)
    dst_ip_str = toIPstr(dst_ip)
    # print(
    #    f"src_mac={src_mac.hex()} dst_mac={dst_mac.hex()} src_ip={src_ip_str} dst_ip={dst_ip_str} proto={proto} src_port={src_port} dst_port={dst_port}"
    # )

    # CA payload
    packet_len = len(packet_bytearray)
    consumed = 0
    while (consumed + payload_offset) < packet_len:
        offset = consumed + payload_offset
        ca_command = int.from_bytes(packet_bytearray[offset : offset + 2], "big")
        ca_payload_size = int.from_bytes(
            packet_bytearray[offset + 2 : offset + 4], "big"
        )

        # print(ca_command)
        # print(CA_COMMANDS.get(ca_command, "KEY_ERROR"))

        # 18: "CA_PROTO_CREATE_CHAN",
        if ca_command == 18:
            if ca_payload_size > 0:
                cid = int.from_bytes(packet_bytearray[offset + 8 : offset + 12], "big")
                pvname = packet_bytearray[
                    offset + 16 : offset + 16 + ca_payload_size
                ].decode()
                # print(f"cid={cid} pvname={pvname}")
                request_pv_table = request_pv_table | {
                    f"{src_ip_str}:{src_port}": {
                        f"{dst_ip_str}:{dst_port}": {cid: pvname}
                    }
                }
            else:
                cid = int.from_bytes(packet_bytearray[offset + 8 : offset + 12], "big")
                sid = int.from_bytes(packet_bytearray[offset + 12 : offset + 16], "big")
                # print(f"sid={sid}")

                pvname = request_pv_table[f"{dst_ip_str}:{dst_port}"][
                    f"{src_ip_str}:{src_port}"
                ][cid]

                connected_pv_table = connected_pv_table | {
                    f"{dst_ip_str}:{dst_port}": {
                        f"{src_ip_str}:{src_port}": {sid: pvname}
                    }
                }
                del request_pv_table[f"{dst_ip_str}:{dst_port}"][
                    f"{src_ip_str}:{src_port}"
                ][cid]
        # 12: "CA_PROTO_CLEAR_CHAN",
        if ca_command == 12:
            sid = int.from_bytes(packet_bytearray[offset + 8 : offset + 12], "big")
            cid = int.from_bytes(packet_bytearray[offset + 12 : offset + 16], "big")

            try:
                del connected_pv_table[f"{dst_ip_str}:{dst_port}"][
                    f"{src_ip_str}:{src_port}"
                ][sid]
            except KeyError:
                pass
        # 4: "CA_PROTO_WRITE",
        if ca_command == 4:
            sid = int.from_bytes(packet_bytearray[offset + 8 : offset + 12], "big")
            cid = int.from_bytes(packet_bytearray[offset + 12 : offset + 16], "big")

            pvname = connected_pv_table[f"{src_ip_str}:{src_port}"][
                f"{dst_ip_str}:{dst_port}"
            ][sid]
            value = packet_bytearray[
                offset + 16 : offset + 16 + ca_payload_size
            ].decode()

            print(
                f"Write: {pvname} {value} from {src_ip_str}:{src_port} to {dst_ip_str}:{dst_port}"
            )

        # print("request")
        # print(request_pv_table)
        # print("connected")
        # pprint(connected_pv_table)
        consumed += 16 + ca_payload_size
