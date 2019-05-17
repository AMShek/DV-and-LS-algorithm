# coding=gbk
import json


class Addr:

    def __init__(self, ip: str = None, mask: int = None, port: int = None):
        self.ip = ip
        self.mask = mask
        self.port = port

    def __str__(self):
        return self.ip + "/" + str(self.mask) + ":" + str(self.port)

    def __eq__(self, other):
        return self.ip == other.ip and self.mask == other.mask and self.port == other.port

def strToAddr(str):
    i=str.find('/')
    ipt=str[0:i];
    j=str.find(':');
    maskt=int(str[i+1:j])
    portt=int(str[j+1:])
    return Addr(ip=ipt,mask=maskt,port=portt);
    
# None链路不可用 
#cost == inf 链路不可用
class NeighborEntry:
    def __init__(self, addr: Addr = None, cost=None, name=None, serialized_entry: str = None):
        if serialized_entry is None:
            self.addr = addr
            self.cost = cost  
            self.name = name
            self.last_heartbeat_time = None
            self.online = False
        else:
            my_obj = json.loads(serialized_entry)
            self.addr = Addr(my_obj["addr"]["ip"], my_obj["addr"]["mask"], my_obj["addr"]["port"])
            self.cost = my_obj["cost"]
            self.name = my_obj["name"]
            self.last_heartbeat_time = ["last_heartbeat_time"]
            self.online = my_obj["online"]

    def serialize(self) -> str:
        return json.dumps(obj=self, default=lambda obj: obj.__dict__)


def serialize_neighbor_list(neighbor_list: [NeighborEntry]):
    str = ""
    for entry in neighbor_list:
        str += entry.serialize() + "\n"
    str = str[:len(str) - 1]
    return str


def deserialize_neighbor_list(str):
    neighbor_list = []
    str_list = str.split("\n")
    for entry_str in str_list:
        neighbor_list.append(NeighborEntry(serialized_entry=entry_str))
    return neighbor_list


class VirtualPacket:
    """
    :type type: int
    :type src: Addr
    :type des: Addr
    :type payload: str
    """

    def __init__(self, src: Addr = None, des: Addr = None, payload: str = None, type=None,
                 serialized_packet: str = None):
        # 从序列化的packet中重建结构化的packet
        if serialized_packet is not None:
            my_obj = json.loads(serialized_packet)
            self.type = my_obj["type"]
            self.src = Addr(my_obj["src"]["ip"], int(my_obj["src"]["mask"]), int(my_obj["src"]["port"]))
            self.des = Addr(my_obj["des"]["ip"], int(my_obj["des"]["mask"]), int(my_obj["des"]["port"]))
            self.payload = my_obj["payload"]
       
        else:
            self.type = type  
            self.src = src
            self.des = des
            self.payload = payload  

    # 将该packet序列化以便网络传输
    def serialize(self) -> str:
        return json.dumps(obj=self, default=lambda obj: obj.__dict__)

    def __str__(self):
        return "***Packet***\ntype: " + str(self.type) + "\n" + \
               "src: " + str(self.src) + "\n" + \
               "des: " + str(self.des) + "\n" + \
               "payload: " + self.payload + "\n************"


class ForwardTableEntry:
    """
    :type des_addr : Addr
    :type next_router_addr: Addr
    """

    def __init__(self, des_addr=None, next_router_addr=None, serialized_entry=None):
        if serialized_entry is None:
            self.des_addr = des_addr
            self.next_router_addr = next_router_addr
        else:
            my_obj = json.loads(serialized_entry)
            self.des_addr = Addr(ip=my_obj["des_addr"]["ip"], mask=my_obj["des_addr"]["mask"],
                                 port=my_obj["des_addr"]["port"])
            self.next_router_addr = Addr(ip=my_obj["next_router_addr"]["ip"], mask=my_obj["next_router_addr"]["mask"],
                                         port=my_obj["next_router_addr"]["port"])

    def __str__(self):
        return "ForwardTableEntry:(des_addr = " + str(self.des_addr) + " next_router_addr= " + str(
            self.next_router_addr) + ")"

    def serialize(self):
        return json.dumps(obj=self, default=lambda obj: obj.__dict__)


def serialize_forward_table(forwardTable):
    str = ""
    for entry in forwardTable:
        str += entry.serialize() + "\n"
    str = str[:len(str) - 1]
    return str


def deserialize_forward_table(str):
    table = []
    str_list = str.split("\n")
    for entry_str in str_list:
        if entry_str == "":
            continue
        table.append(ForwardTableEntry(serialized_entry=entry_str))
    return table
