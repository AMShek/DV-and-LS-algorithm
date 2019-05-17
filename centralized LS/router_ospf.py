import random
import threading
import time
from socket import socket, AF_INET, SOCK_DGRAM

from DataStructure import *
from utils import addr2name


def receive_virtual_packet(packet: VirtualPacket):
    # 调用与数据包类型对应的处理函数
    if packet.type == 0:
        handle_normal_packet(packet)
    elif packet.type == 5:
        handle_ospf_forward_table_packet(packet)
    elif packet.type == 3:
        handle_heartbeat_packet(packet)
    elif packet.type == 4:
        handle_heartbeat_response_packet(packet)
    return


def handle_normal_packet(packet: VirtualPacket):
    print("Receive packet from ", packet.src, "des=", packet.des, "payload=", packet.payload)
    if packet.des == local_addr:
        consume_virtual_packet(packet)
        return

    for entry in forwardTable:
        if entry.des_addr == packet.des:
            print("Forwarding to ", str(entry))
            send_virtual_packet(packet, entry.next_router_addr)
            return


def handle_heartbeat_packet(packet: VirtualPacket):
    response_packet = construct_heartbeat_response_packet(packet.src)
    send_virtual_packet(response_packet, packet.src)


def construct_heartbeat_packet(des: Addr):
    return VirtualPacket(type=3, src=local_addr, des=des, payload=router_name)


def construct_heartbeat_response_packet(des: Addr):
    return VirtualPacket(type=4, src=local_addr, des=des, payload=router_name)


def handle_heartbeat_response_packet(packet: VirtualPacket):
    if packet.payload == "controller":
        if not controller["online"]:
            controller["online"] = True
            packet = construct_neighbor_list_packet(controller["addr"])
            send_virtual_packet(packet, controller["addr"])
            print("Controller is online.")

        controller["last_heartbeat_time"] = time.time()
        return
    for entry in neighbour_list:
        if entry.addr == packet.src:
            lock_neighbour_list.acquire()
            entry.last_heartbeat_time = time.time()
            if not entry.online:
                entry.name = packet.payload
                on_neighbor_online(entry)

            entry.online = True
            lock_neighbour_list.release()
            return


def send_virtual_packet(packet: VirtualPacket, des: Addr):
    soc = socket(AF_INET, SOCK_DGRAM)
    while True:
        try:
            port_random = random.randint(10000, 60000)
            while port_random == local_addr.port:
                port_random = random.randint(10000, 60000)
            soc.bind((local_addr.ip, port_random))
            break
        except Exception:
            pass

    soc.sendto(packet.serialize().encode(), (des.ip, des.port))
    soc.close()


def consume_virtual_packet(packet: VirtualPacket):
    print("**Local host is the destination of this packet.")


class UdpListenerThread(threading.Thread):
    def __init__(self, local_addr, threadName):
        super(UdpListenerThread, self).__init__(name=threadName)
        self.udpServerSocket = socket(AF_INET, SOCK_DGRAM)
        self.udpServerSocket.bind((local_addr.ip, local_addr.port))

    def run(self):
        while True:
            raw_data, addr = self.udpServerSocket.recvfrom(1024)
            packet = VirtualPacket(serialized_packet=bytes.decode(raw_data))
            receive_virtual_packet(packet)


def construct_neighbor_list_packet(des: Addr):
    payload = serialize_neighbor_list(neighbour_list)
    packet = VirtualPacket(src=local_addr, des=des, type=6, payload=payload)
    return packet


def handle_ospf_forward_table_packet(packet: VirtualPacket):
    global forwardTable
    table = packet.payload
    forwardTable = deserialize_forward_table(table)

    def printForwardTable(table):
        i = 1
        for entry in forwardTable:
            print(i, "next_hop:", addr2name(entry.next_router_addr), "des:", addr2name(entry.des_addr))
            i += 1

    print("Get Forward Table:")
    printForwardTable(forwardTable)


def on_neighbor_online(entry):
    # 更新链路状态表（邻居表）
    entry.online = True
    # 将新的链路状态表（邻居表）发送到控制器
    packet = construct_neighbor_list_packet(controller["addr"])
    send_virtual_packet(packet, controller["addr"])
    print("Neighbor", entry.name, "is online")


def on_neighbor_offline(neighbor):
    # 更新链路状态表（邻居表）
    neighbor.online = False
    # 将新的链路状态表（邻居表）发送到控制器
    print(controller["addr"])
    packet = construct_neighbor_list_packet(controller["addr"])
    send_virtual_packet(packet, controller["addr"])
    print("Neighbour", neighbor.name, "is offline")


class NeighborWatcher(threading.Thread):
    def __init__(self, threadName):
        super(NeighborWatcher, self).__init__(name=threadName)

    def run(self):
        while True:
            if controller["online"] == True and time.time() - controller["last_heartbeat_time"] >= 2:
                controller["online"] = False
                print("Controller is offline.")
            for neighbor in neighbour_list:
                # 将离线的邻居的代价设为None
                if neighbor.last_heartbeat_time is not None and \
                        neighbor.online and \
                                        time.time() - neighbor.last_heartbeat_time >= 2:
                    on_neighbor_offline(neighbor)
                # 向邻居发送心跳包
                packet = construct_heartbeat_packet(neighbor.addr)
                send_virtual_packet(packet, neighbor.addr)
            # 向控制器发送心跳包
            packet = construct_heartbeat_packet(controller["addr"])
            send_virtual_packet(packet, controller["addr"])
            time.sleep(1)


# 全局变量
local_addr = Addr()
neighbour_list = []
forwardTable = []  # 元素是ForwardTableEntry
controller = {"addr": None, "online": None, "last_heartbeat_time": None}
lock_neighbour_list = threading.Lock()
lock_forwardTable = threading.Lock()


def read_addr_by_name(router_name):
    addr = Addr()
    file = open("routerConfigurationFile/" + router_name + ".txt")
    addr.ip = file.readline().replace("\n", "")
    addr.mask = int(file.readline())
    addr.port = int(file.readline())
    file.close()
    return addr


def read_neighbours_from_file(filepath):
    neighbour_list = []
    file = open(filepath)
    lines = file.readlines()
    for line in lines:
        if line.replace(" ", "")[0] == "#":
            continue
        line_split = line.split(" ")
        if line_split[0] == router_name:
            neighbour_list.append(
                NeighborEntry(name=line_split[1], addr=read_addr_by_name(line_split[1]), cost=int(line_split[2])))
        elif line_split[1] == router_name:
            neighbour_list.append(
                NeighborEntry(name=line_split[0], addr=read_addr_by_name(line_split[0]), cost=int(line_split[2])))
    return neighbour_list


if __name__ == "__main__":
    # 从文件中读取本机地址和邻居列表
    print("Please name this router as a file's name in configuration folder")
    router_name = input()
    local_addr = read_addr_by_name(router_name)
    print("Router", router_name, "is running... Local Address is", str(local_addr))
    neighbour_list = read_neighbours_from_file("routerConfigurationFile/edges.txt")

    # 从文件中读入控制器的地址
    controller["addr"] = read_addr_by_name("controller")
    # 启动UDP数据包监听线程
    UdpListenerThread(local_addr, "thread-UDPListener").start()

    # 启动链路监视，用以向邻居发送心跳包、将2秒内没有收到心跳包的邻居设为离线。邻居的回复由上面的UDP监听线程接收和处理。
    NeighborWatcher("thread-NeighborWatcher").start()
