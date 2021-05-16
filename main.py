import threading
import socket
import os
import argparse
import netifaces
import struct
import fcntl
import sys
import time

# CUSTOM IMPORTS
from imports.headers import IPHeader, ESPHeader, unpack_ipv4
from imports.aes import AESCipher


# ---------- File Descriptors -----------
def read_from_fd(fd):
    packet = os.read(fd, 1024)
    return packet


def write_to_fd(fd, packet_from_socket):
    os.write(fd, packet_from_socket)


def initiate_tun_fd(dev_name):
    # CONSTANTS
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_TAP = 0x0002
    IFF_NO_PI = 0x1000

    # Open TUN device file.
    tun = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', dev_name, IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun, TUNSETIFF, ifr)

    return tun

# -------- END : File Descriptors ----------


# ------- Sockets and Networking ---------
def create_sockets(interface_name):
    # Create a RAW Socket to send the traffic
    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Raw socket to recv the traffic
    receiver = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    receiver.bind((interface_name, 0))

    return sender, receiver


def send_packets(sock: socket.socket, host_ip: str, dst_ip: str, cipher: AESCipher, fd):
    ip_h = IPHeader(host_ip, dst_ip)  # create an IP header
    packet_from_fd = read_from_fd(fd)  # read the file descriptor for packets

    while packet_from_fd:
        encrypted_packet = cipher.encrypt(
            packet_from_fd)  # encrypt the packet using AES
        # create esp header with encrypted packet
        esp_h = ESPHeader(encrypted_packet)

        # create final packet with payload
        packet = (ip_h.header + esp_h.payload)
        # send packet to destination ip
        sock.sendto(packet, (dst_ip, 0))
        # re-read from the FD and loop
        packet_from_fd = read_from_fd(fd)


def recv_packets(sock: socket.socket, host_ip: str, dst_ip: str, cipher: AESCipher, fd):
    packet_from_socket = sock.recv(2048)

    while packet_from_socket:
        # unpack the packet read from the FD
        src, dst, protocol = unpack_ipv4(packet_from_socket[14:35])

        # protocol 50 == ESP Header
        if protocol == 50:
            decrypted_packet = cipher.decrypt(
                packet_from_socket[42:])  # decrypt the packet
            # write to file descriptor so it can be read and sent
            write_to_fd(fd, decrypted_packet)

        packet_from_socket = sock.recv(2048)

# ------- END : Sockets and Networking ---------


# function gets user arguments and returns an object
def user_args():
    parser = argparse.ArgumentParser(allow_abbrev=False, description="Tunnel")

    parser.add_argument("interface", help="Interface to be binded to.")
    parser.add_argument('--destination-ip', '-dst', action='store',type=str, help="Destination IP", required=True)
    parser.add_argument('--encrypt-key', '-key', action='store', type=str,help="Encryption key used for connection", required=True)
    parser.add_argument('--tun-int-name', '-tun', action='store',type=str, help="TUN int name", required=True)
    args = parser.parse_args()

    return args


if __name__ == "__main__":
    # Get user arguments
    args = user_args()

    # Create cipher with key from args
    cipher = AESCipher(args.encrypt_key)
    # Open the tunnel to an IO Stream
    fd = initiate_tun_fd(args.tun_int_name.encode())
    # Create sockets for sending and recieving
    sender, receiver = create_sockets(args.interface)
    # Get the IP from interface name
    host_ip = netifaces.ifaddresses(args.interface)[2][0]['addr']

    # Create threads for sending and receiving packets
    sendT = threading.Thread(target=send_packets, args=(
        sender, host_ip, args.destination_ip, cipher, fd))
    recvT = threading.Thread(target=recv_packets, args=(
        receiver, host_ip, args.destination_ip, cipher, fd))

    # Begin threads
    sendT.setDaemon(True)
    sendT.start()
    recvT.setDaemon(True)
    recvT.start()

    print("Tunnel is open and running...")
    while True:
        try:
            for _ in range(10):
                time.sleep(0.2)
        except KeyboardInterrupt:
            sys.exit(1)

            
