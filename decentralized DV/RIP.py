# coding=gbk
import random
import threading
import time
from socket import socket, AF_INET, SOCK_DGRAM

from DataStructure import *
from utils import *

def receive_virtual_packet(packet: VirtualPacket):
    if packet.type == 0:
        handle_normal_packet(packet)
    elif packet.type == 1:
        handle_request_packet(packet)
    elif packet.type == 2:
        handle_distance_vector_packet(packet)
    elif packet.type == 3:
        handle_heartbeat_packet(packet)
    elif packet.type == 4:
        handle_heartbeat_response_packet(packet)
    return


def handle_normal_packet(packet: VirtualPacket):
    print("Received(forwarding) Normal Packet, src=", packet.src, "des=", packet.des, "payload=", packet.payload)
    if packet.des == local_addr:
        consume_virtual_packet(packet)
        return

    for entry in forwardTable:
        if entry.des_addr == packet.des:
            print("Forwarding to", str(entry))
            send_virtual_packet(packet, entry.next_router_addr)
            return



def handle_request_packet(packet: VirtualPacket):
    pass


def handle_distance_vector_packet(packet: VirtualPacket):
    pass


def handle_heartbeat_packet(packet: VirtualPacket):
    response_packet = construct_heartbeat_response_packet(packet.src)
    send_virtual_packet(response_packet, packet.src)


def handle_heartbeat_response_packet(packet: VirtualPacket):
    for entry in neighbour_list:
        if entry.addr == packet.src:
            lock_neighbour_list.acquire()
            entry.last_heartbeat_time = time.time()
            if not entry.online:
                entry.name = packet.payload
                print("Neighbor", entry.name, "is online")
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



def handle_request_packet(packet: VirtualPacket):
    send_virtual_packet(construct_distance_vector_packet(packet.src),packet.src)
    pass


def handle_distance_vector_packet(packet: VirtualPacket):
    dis_vector = payload_to_distance_vector(packet.payload)
    lock_distance_vector_list.acquire()
    distance_vector_list[packet.src.__str__()] = dis_vector
    lock_distance_vector_list.release()
    pass


def construct_distance_vector_packet(des: Addr):
    return VirtualPacket(type=2, src=local_addr, des=des, payload=distance_vector_to_payload(distance_vector))
    pass


def request_distance_vector():
    for neighbor in neighbour_list:
        send_virtual_packet(VirtualPacket(type=1, src=local_addr, des=neighbor.addr, payload=""),des=neighbor.addr)
    pass


def construct_heartbeat_packet(des: Addr):
    return VirtualPacket(type=3, src=local_addr, des=des, payload=router_name)


def construct_heartbeat_response_packet(des: Addr):
    return VirtualPacket(type=4, src=local_addr, des=des, payload=router_name)


def construct_request_distance_vector_packet(des: Addr):
    return VirtualPacket(type=1, src=local_addr, des=des, payload="")


# �����ݰ��е�payload����ת��Ϊһ��distance_vector
def payload_to_distance_vector(payload):
    return eval(payload)
    pass


# ��distance_vectorת��Ϊstr�Թ��������ݰ�
def distance_vector_to_payload(dis_vector):
    return str(dis_vector)
    pass



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

#�ж��ھ��Ƿ������Լ����ͼ�����
class NeighborWatcher(threading.Thread):
    def __init__(self, threadName):
        super(NeighborWatcher, self).__init__(name=threadName)

    def run(self):
        while True:
            for neighbor in neighbour_list:
                if neighbor.last_heartbeat_time is not None and \
                        neighbor.online and \
                                        time.time() - neighbor.last_heartbeat_time >= 2:
                    neighbor.online = False
                    print("Neighour", neighbor.name, "is offline")
                packet = construct_heartbeat_packet(neighbor.addr)
                send_virtual_packet(packet, neighbor.addr)
            time.sleep(1)


local_addr = Addr()
neighbour_list = []
forwardTable = []  
distance_vector = {}
distance_vector_list = {}
lock_neighbour_list = threading.Lock()
lock_forwardTable = threading.Lock()
lock_distance_vector = threading.Lock()
lock_distance_vector_list = threading.Lock()


def read_addr_by_name(router_name):
    addr = Addr()
    file = open("C:/Users/Administrator/Desktop/routerConfigurationFile/" + router_name + ".txt")
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
                NeighborEntry(name=line_split[1], addr=read_addr_by_name(line_split[1]), cost=line_split[2]))
        elif line_split[1] == router_name:
            neighbour_list.append(
                NeighborEntry(name=line_split[0], addr=read_addr_by_name(line_split[0]), cost=line_split[2]))
    return neighbour_list

def setForwardTable(dst,next):
    flag = True
    for var in forwardTable:
        if var.des_addr == dst:
            var.next_router_addr = next;
            flag = False;
    if flag:
        forwardTable.append(ForwardTableEntry(des_addr=dst, next_router_addr=next))
    return

def printForwardTable(table):
    i = 1
    for entry in forwardTable:
        print(i, "next_hop:", addr2name(entry.next_router_addr), "des:", addr2name(entry.des_addr))
        i += 1

if __name__ == "__main__":
    # ���ļ��ж�ȡ������ַ���ھ��б�
    print("Please input the name of this router(must match a file in configuration folder)")
    router_name = input()
    local_addr = read_addr_by_name(router_name)
    print("Router", router_name, "is running... Local Address is", str(local_addr))
    neighbour_list = read_neighbours_from_file("C:/Users/Administrator/Desktop/routerConfigurationFile/edges.txt")

    # ����UDP���ݰ������߳�
    UdpListenerThread(local_addr, "thread-UDPListener").start()

    # ������·����
    NeighborWatcher("thread-NeighborWatcher").start()

    lock_distance_vector.acquire();
    distance_vector[local_addr.__str__()]=0;
    lock_distance_vector.release();


    while True:
        request_distance_vector()
        lock_distance_vector.acquire()
        lock_forwardTable.acquire()

        distance_vector={};
        distance_vector[local_addr.__str__()] = 0;
        forwardTable = [];

        for keyI in distance_vector_list:
            for keyJ in distance_vector_list[keyI]:
                theKI= None
                for var in neighbour_list:
                    if strToAddr(keyI)==var.addr:
                        theKI=var;
                if theKI.online==False:
                    break
                basic_cost= theKI.cost

                if keyJ in distance_vector:
                    if distance_vector_list[keyI][keyJ]+int(basic_cost)<distance_vector[keyJ]:
                        distance_vector[keyJ]=distance_vector_list[keyI][keyJ]+int(basic_cost);
                        setForwardTable(strToAddr(keyJ), strToAddr(keyI));
                else:
                    distance_vector[keyJ] = distance_vector_list[keyI][keyJ] + int(basic_cost);
                    setForwardTable(strToAddr(keyJ), strToAddr(keyI));
        dv=distance_vector.copy()
        for key in distance_vector:
            if distance_vector[key]>=8:
                dv.pop(key);
        distance_vector=dv;


        lock_forwardTable.release()
        lock_distance_vector.release()
        printForwardTable(forwardTable)
        print ("\n")
        time.sleep(0.5);
