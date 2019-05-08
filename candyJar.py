
# coding: utf-8

# In[8]:


import socket
from datetime import datetime
from random import getrandbits
from ipaddress import IPv4Address
from netaddr import IPNetwork, IPAddress
import threading
import requests
from urllib.request import urlopen
import json


# In[9]:


print('''Don't Mess With Network List from Mirai:
127.0.0.0/8               # Loopback
0.0.0.0/8                 # Invalid address space
3.0.0.0/8                 # General Electric (GE)
15.0.0.0/7                # Hewlett-Packard (HP)
56.0.0.0/8                # US Postal Service
10.0.0.0/8                # Internal network
192.168.0.0/16            # Internal network
172.16.0.0/14             # Internal network
100.64.0.0/10             # IANA NAT reserved
169.254.0.0/16            # IANA NAT reserved
198.18.0.0/15             # IANA Special use
224.0.0.0/4               # Multicast
6.0.0.0/7                 # Department of Defense 
11.0.0.0/8                # Department of Defense
21.0.0.0/8                # Department of Defense
22.0.0.0/8                # Department of Defense
26.0.0.0/8                # Department of Defense
28.0.0.0/7                # Department of Defense
30.0.0.0/8                # Department of Defense
33.0.0.0/8                # Department of Defense
55.0.0.0/8                # Department of Defense
214.0.0.0/7               # Department of Defense''')


# In[10]:


dontMessWithList = ['127.0.0.0/8', '0.0.0.0/8', '3.0.0.0/8', '15.0.0.0/7', '56.0.0.0/8', '10.0.0.0/8', '192.168.0.0/16', '172.16.0.0/14', '100.64.0.0/10', '169.254.0.0/16', '198.18.0.0/15', '224.0.0.0/4', '6.0.0.0/7', '11.0.0.0/8', '21.0.0.0/8', '22.0.0.0/8', '26.0.0.0/8', '28.0.0.0/7', '30.0.0.0/8', '33.0.0.0/8', '55.0.0.0/8', '214.0.0.0/7']


# In[11]:


def generate_rand_ip():
    ip_in_bits = getrandbits(32)
    ip_addr = IPv4Address(ip_in_bits)
    rand_ip_addr = str(ip_addr)
    return rand_ip_addr


# In[12]:


def check_ip(ip_addr):
    for network in dontMessWithList:
        if IPAddress(ip_addr) in IPNetwork(network):
            return False
    return True


# In[13]:


print('Some standard ports: \nTR-069:\t7547\nUPnP:\t1900\nXMPP:\t5222\nCoAP:\t5683\nMQTT:\t1883/8883')


# In[14]:


def TCP_connect(ip, port_number, delay, output):
    TCPsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCPsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    TCPsock.settimeout(delay)
    try:
        TCPsock.connect((ip, port_number))
        output[port_number] = 'Listening'
    except:
        output[port_number] = ''


def scan_ports(host_ip, delay):

#     print("-" * 60)
#     print("Please wait, scanning remote host", host_ip)
#     print("-" * 60)

    t1 = datetime.now()

    threads = []
    output = {}
    common_iot_ports = [21, 22, 23, 25, 80, 81, 82, 83, 84, 88, 137, 143, 443, 445, 554, 631, 1080, 1883, 1900, 2000, 2323, 4433, 4443, 4567, 5222, 5683, 7474, 7547, 8000, 8023, 8080, 8081, 8443, 8088, 8883, 8888, 9000, 9090, 9999, 10000, 37777, 49152]

    for i in common_iot_ports:
        t = threading.Thread(target=TCP_connect, args=(host_ip, i, delay, output))
        threads.append(t)

    for i in range(len(common_iot_ports)):
        threads[i].start()
    
    for i in range(len(common_iot_ports)):
        threads[i].join()
    
    total_listening = 0
    ports_listening = []
    for i in range(len(common_iot_ports)):
        if output[common_iot_ports[i]] == 'Listening':
            total_listening += 1
            ports_listening.append(common_iot_ports[i])
#             print(str(common_iot_ports[i]) + ': ' + output[common_iot_ports[i]])

#     t2 = datetime.now()
#     total =  t2 - t1
#     print('Scanning completed in:', total)
    if total_listening > 0:
        print("IP:", host_ip)
        print(total_listening, ports_listening)
    return total_listening, ports_listening


# In[25]:


def check_if_phue_bulb(ip_addr, port):
    url = 'http://' + ip_addr + ':' + str(port)
    try:
        r = requests.get(url, verify=False, timeout=2)
        return r.headers
        r = urlopen(url, timeout=3, verify=False)
        string = r.read().decode('utf-8')
        json_obj = json.loads(string)
        return json_obj
    except Exception as e:
        return "Empty json object"


# In[100]:


import pickle

def storeData(obj, filename):
    pickleFile = open(filename, 'wb')
    pickle.dump(obj, pickleFile)
    pickleFile.close()
    
def loadData(filename):
    pickleFile = open(filename, 'rb')
    obj = pickle.load(pickleFile)
    pickleFile.close()
    return obj


# In[112]:


# r = requests.get('http://194.132.63.12:')
# r.headers
ips_checked = loadData("ips_checked.dat")
hikvision_camera_addr = loadData("hikvision_camera_addr.dat")
sonicWall_firewall_addr = loadData("sonicWall_firewall_addr.dat")
netgear_router_addr = loadData("netgear_router_addr.dat")
TR069_protocolDevice_addr = loadData("TR069_protocolDevice_addr.dat")
lighttpd_protocolDevice_addr = loadData("lighttpd_protocolDevice_addr.dat")
Huawei_router_addr = loadData("Huawei_router_addr.dat")
kangle_addr = loadData("kangle_addr.dat")
tplink_router_addr = loadData("tplink_router_addr.dat")
app_web_server_addr = loadData("app_web_server_addr.dat")


# In[ ]:


try:
    while True:
        ip_addr = generate_rand_ip()
        if ip_addr not in ips_checked:
            ips_checked.add(ip_addr)
        else:
            continue
    #     ip_addr = '73.162.12.235'
        if check_ip(ip_addr):
            a, b = scan_ports(ip_addr, 2)
            if a > 0:
                for port in b:
    #                 print("Reading port:", port)
                    json_obj = check_if_phue_bulb(ip_addr, port)
#                     print(json_obj)
                    if json_obj != "Empty json object":
                        rh = json.dumps(json_obj.__dict__['_store'])
                        print(rh)
                        if 'Hikvision'.lower() in rh.lower() or 'DVRDVS'.lower() in rh.lower():
                            hikvision_camera_addr.add(ip_addr + ":" + str(port))
                        elif 'SonicWALL'.lower() in rh.lower():
                            sonicWall_firewall_addr.add(ip_addr + ":" + str(port))
                        elif 'NETGEAR'.lower() in rh.lower():
                            netgear_router_addr.add(ip_addr + ":" + str(port))
                        elif 'TR069'.lower() in rh.lower() or 'gSOAP'.lower() in rh.lower() or 'TR-069'.lower() in rh.lower():
                            TR069_protocolDevice_addr.add(ip_addr + ":" + str(port))
                        elif 'lighttpd'.lower() in rh.lower():
                            lighttpd_protocolDevice_addr.add(ip_addr + ":" + str(port))
                        elif 'HuaweiHomeGateway'.lower() in rh.lower():
                            Huawei_router_addr.add(ip_addr + ":" + str(port))
                        elif 'kangle'.lower() in rh.lower():
                            kangle_addr.add(ip_addr + ":" + str(port))
                        elif 'TP-LINK'.lower() in rh.lower():
                            tplink_router_addr.add(ip_addr + ":" + str(port))
                        elif 'App-webs'.lower() in rh.lower():
                            app_web_server_addr.add(ip_addr + ":" + str(port))
                    if 'name' in json_obj:
                        if json_obj['name'] == 'Philips hue':
                            print(("*" * 10) + 'Philips hue bulb is found.' + ("*" * 10))
    #                 print()
    #     else:
    #         print(ip_addr, "is in excluded ip list.")
    #     break
except KeyboardInterrupt:
    pass


# In[ ]:


print("Total unique IPs checked:", len(ips_checked))
print("Total unique hikvision cameras found:", len(hikvision_camera_addr))
print("Total unique sonicWall firewall found:", len(sonicWall_firewall_addr))
print("Total unique netgear router found:", len(netgear_router_addr))
print("Total unique TR069_protocolDevice found:", len(TR069_protocolDevice_addr))
print("Total unique lighttpd_protocolDevice found:", len(lighttpd_protocolDevice_addr))
print("Total unique Huawei_router found:", len(Huawei_router_addr))
print("Total unique kangle found:", len(kangle_addr))
print("Total unique tplink_router found:", len(tplink_router_addr))
print("Total unique app_web_server found:", len(app_web_server_addr))


# In[ ]:


print(hikvision_camera_addr)
print(sonicWall_firewall_addr)
print(netgear_router_addr)
print(TR069_protocolDevice_addr)
print(lighttpd_protocolDevice_addr)
print(Huawei_router_addr)
print(kangle_addr)
print(tplink_router_addr)
print(app_web_server_addr)


# In[ ]:


storeData(ips_checked, "ips_checked.dat")
storeData(hikvision_camera_addr, "hikvision_camera_addr.dat")
storeData(sonicWall_firewall_addr, "sonicWall_firewall_addr.dat")
storeData(netgear_router_addr, "netgear_router_addr.dat")
storeData(TR069_protocolDevice_addr, "TR069_protocolDevice_addr.dat")
storeData(lighttpd_protocolDevice_addr, "lighttpd_protocolDevice_addr.dat")
storeData(Huawei_router_addr, "Huawei_router_addr.dat")
storeData(kangle_addr, "kangle_addr.dat")
storeData(tplink_router_addr, "tplink_router_addr.dat")
storeData(app_web_server_addr, "app_web_server_addr.dat")

from collections import defaultdict
port_dict = defaultdict(lambda : 0)
for i in hikvision_camera_addr:
    port_dict[i.split(':')[1]] += 1
for i in sonicWall_firewall_addr:
    port_dict[i.split(':')[1]] += 1
for i in netgear_router_addr:
    port_dict[i.split(':')[1]] += 1
for i in TR069_protocolDevice_addr:
    port_dict[i.split(':')[1]] += 1
for i in lighttpd_protocolDevice_addr:
    port_dict[i.split(':')[1]] += 1
for i in Huawei_router_addr:
    port_dict[i.split(':')[1]] += 1
for i in kangle_addr:
    port_dict[i.split(':')[1]] += 1
for i in tplink_router_addr:
    port_dict[i.split(':')[1]] += 1
for i in app_web_server_addr:
    port_dict[i.split(':')[1]] += 1

print(port_dict)
