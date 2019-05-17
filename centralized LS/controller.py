import random
import threading
import time
from socket import socket, AF_INET, SOCK_DGRAM

from DataStructure import *

slave_list = []  # element: (Addr, last_time_heartbeat)


def addr2slave(addr: Addr):
    for slave in slave_list:
        if slave["addr"] == addr:
            return slave
    return None

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


class SlaveWatcher(threading.Thread):
    def __init__(self, threadName):
        super(SlaveWatcher, self).__init__(name=threadName)

    def run(self):
        while True:
            for slave in slave_list:
                # 发送心跳侦测包
                packet = construct_heartbeat_packet(slave["addr"])
                send_virtual_packet(packet, slave["addr"])
                # 检查slave是否离线
                if slave["online"] == True and \
                                slave.get("last_heartbeat_time") is not None and \
                                        time.time() - slave["last_heartbeat_time"] >= 2:
                    set_slave_offline(slave)

            time.sleep(1)


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


def handle_heartbeat_packet(packet: VirtualPacket):
    slave = addr2slave(packet.src)
    slave["name"] = packet.payload

    response_packet = construct_heartbeat_response_packet(packet.src)
    send_virtual_packet(response_packet, packet.src)


def construct_heartbeat_packet(des: Addr):
    return VirtualPacket(type=3, src=local_addr, des=des, payload=controller_name)


def construct_heartbeat_response_packet(des: Addr):
    return VirtualPacket(type=4, src=local_addr, des=des, payload=controller_name)


def handle_heartbeat_response_packet(packet):
    slave = addr2slave(packet.src)
    slave["name"] = packet.payload
    slave["last_heartbeat_time"] = time.time()
    if not slave["online"]:
        set_slave_online(slave)


def set_slave_online(slave, str=""):
    if slave["online"]:
        return

    slave["online"] = True
    if slave.get("name") is not None:
        print(str + "Slave", slave["name"], "is online.")
    else:
        print(str + "Slave", slave["addr"], "is online.")


def set_slave_offline(slave, str=""):
    if not slave["online"]:
        return

    slave["online"] = False
    slave["neighbor_list"] = []
    slave["forward_table"] = []
    for i in range(len(cost_table)):
        cost_table[slave["num"]][i] = float("inf")
        cost_table[i][slave["num"]] = float("inf")
    if slave.get("name") is not None:
        print(str + "Slave", slave["name"], "is offline.")
    else:
        print(str + "Slave", slave["addr"], "is offline.")


def run_dijkstra_algorithm():
    def is_neighbor(u, v):
        return cost_table[u["num"]][v["num"]] != float("inf")

    def cost(u, v):
        if u == v:
            return 0
        return cost_table[u["num"]][v["num"]]

    def find_minium_node_outside_N():
        node = None
        min_cost = None
        prev = None
        for node_inside_N in N_:
            for neighbor in get_neighbor_list(node_inside_N):
                if neighbor in N_: continue
                if min_cost is None or cost(node_inside_N, neighbor) < min_cost:
                    min_cost = cost(node_inside_N, neighbor)
                    node = neighbor
                    prev = node_inside_N
        return node, prev

    def get_neighbor_list(w):
        w_neighbor_list = []
        for slave in slave_list:
            if is_neighbor(w, slave):
                w_neighbor_list.append(slave)
        return w_neighbor_list

    def get_num_of_online_slaves():
        num = 0
        for slave in slave_list:
            if slave["online"]:
                num += 1
        return num

    for u in slave_list:
        if u["online"] is False:
            continue
        print("Source node in this step is", u["name"])
        D = {}
        D[u["num"]] = 0
        p = {}
        N_ = [u]
        for v in slave_list:
            if u == v:
                continue
            elif v["online"] is True and is_neighbor(u, v):
                D[v["num"]] = cost(u, v)
            else:
                D[v["num"]] = float("inf")
        num_of_online_slaves = get_num_of_online_slaves()
        print("The number of online slaves online:", num_of_online_slaves)
        while len(N_) < num_of_online_slaves:
            print("len(N'):", len(N_))
            w, prev = find_minium_node_outside_N()
            if w is None: break
            N_.append(w)
            p[w["num"]] = prev
            print("w:", w["name"], "prev:", prev["name"])
            for v in get_neighbor_list(w):
                D[v["num"]] = min(D[v["num"]], D[w["num"]] + cost(w, v))
        u["forward_table"] = []
        print("Least cost:", D)
        for slave in slave_list:
            if slave == u or D[slave["num"]] == float("inf"):
                continue
            next_router = slave
            while p[next_router["num"]] != u:
                next_router = p[next_router["num"]]
            u["forward_table"].append(
                ForwardTableEntry(des_addr=slave["addr"],
                                  next_router_addr=next_router["addr"]
                                  ))


def send_forward_table_packet(slave):
    table_str = serialize_forward_table(slave["forward_table"])
    packet = VirtualPacket(src=local_addr, des=slave["addr"], type=5, payload=table_str)
    send_virtual_packet(packet, slave["addr"])


def handle_ospf_neighbor_list_packet(packet: VirtualPacket):
    slave = addr2slave(packet.src)
    print("Receive the packet from", slave["name"], slave["addr"])
    slave["neighbor_list"] = deserialize_neighbor_list(packet.payload)
    set_slave_online(slave)
    for neighbor in slave["neighbor_list"]:
        slave2 = addr2slave(neighbor.addr)
        if neighbor.online:
            # 根据新邻居表更新在线状态表
            set_slave_online(slave2)
            # 根据新邻居表更新邻接矩阵
            cost_table[slave["num"]][slave2["num"]] = neighbor.cost
            cost_table[slave2["num"]][slave["num"]] = neighbor.cost

    print("Route the packet using dijkstra algorithm", slave["name"], slave["addr"])
    printMat(cost_table)
    run_dijkstra_algorithm()
    for slave in slave_list:
        if slave["online"]:
            send_forward_table_packet(slave)


def receive_virtual_packet(packet: VirtualPacket):
    # 调用与数据包类型对应的处理函数
    if packet.type == 3:
        handle_heartbeat_packet(packet)
    elif packet.type == 4:
        handle_heartbeat_response_packet(packet)
    elif packet.type == 6:
        print("Receive OSPF neighbor list")
        handle_ospf_neighbor_list_packet(packet)
    return


def read_addr_by_name(router_name):
    addr = Addr()
    file = open("routerConfigurationFile/" + router_name + ".txt")
    addr.ip = file.readline().replace("\n", "")
    addr.mask = int(file.readline())
    addr.port = int(file.readline())
    file.close()
    return addr


def printMat(mat):
    mstr = ""
    for r in mat:
        for cell in r:
            mstr += str(cell) + " "
        mstr += "\n"
    print(mstr)

def initController():
    global local_addr, slave_list, cost_table
    local_addr = Addr()
    file = open("routerConfigurationFile/" + controller_name + ".txt")
    local_addr.ip = file.readline().replace("\n", "")
    local_addr.mask = int(file.readline())
    local_addr.port = int(file.readline())
    file.readline()
    line = file.readline()
    i = 0
    while line:
        slave_name = line.replace("\n", "")
        slave_addr = read_addr_by_name(slave_name)
        slave_list.append({"num": i,
                           "addr": slave_addr,
                           "last_heartbeat_time": None,
                           "online": False,
                           "name": slave_name,
                           "neighbor_list": [],
                           "forward_table": []})
        line = file.readline()
        i += 1

    cost_table = [[float("inf") for i in range(len(slave_list))] for i in range(len(slave_list))]


controller_name = "controller"
initController()

print("Centralized routing using controller... Local Address is", str(local_addr))
UdpListenerThread(local_addr, "thread-UDPListener").start()
SlaveWatcher("thread-SlaveWatcher").start()
