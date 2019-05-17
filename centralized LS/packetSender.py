# 用于发送第一个UDP数据包和debug
import random
from socket import socket, AF_INET, SOCK_DGRAM

from DataStructure import *
from router_ospf import read_addr_by_name

file = open("routerConfigurationFile/packetSender.txt")
first_router_name = file.readline().replace("first-router:", "").replace("\n", "")
des_router_name = file.readline().replace("des-router:", "").replace("\n", "")
first_router = read_addr_by_name(first_router_name)
des_router = read_addr_by_name(des_router_name)

port = random.randint(3000, 60000)
udpServerSocket = socket( AF_INET, SOCK_DGRAM )
udpServerSocket.bind(("127.0.0.1", port))

packet = VirtualPacket(payload="i am payload", src=Addr("127.0.0.1", 24, port), des=des_router, type=0)
udpServerSocket.sendto(packet.serialize().encode(), (first_router.ip, first_router.port))
