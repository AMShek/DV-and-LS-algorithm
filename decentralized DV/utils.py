from DataStructure import *

slave_list = []


def initController():
    file = open("C:/Users/Administrator/Desktop/routerConfigurationFile/" + "controller" + ".txt")
    file.readline()
    file.readline()
    file.readline()
    file.readline()
    line = file.readline()

    def read_addr_by_name(router_name):
        addr = Addr()
        file = open("C:/Users/Administrator/Desktop/routerConfigurationFile/" + router_name + ".txt")
        addr.ip = file.readline().replace("\n", "")
        addr.mask = int(file.readline())
        addr.port = int(file.readline())
        file.close()
        return addr

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


def addr2name(addr: Addr):
    slave = addr2slave(addr)
    if slave is not None:
        return slave["name"]
    return None


def addr2slave(addr: Addr):
    for slave in slave_list:
        if slave["addr"] == addr:
            return slave
    return None


initController()
