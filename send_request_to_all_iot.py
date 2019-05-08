import requests
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

headers = {'User-Agent': None, 'Host': None, 'Accept-Encoding': None, 'Accept': None, 'Connection': None}

response_from_iot = loadData('response_from_iot.dat')

tr069_ips = loadData('TR069_protocolDevice_addr.dat')

for i in tr069_ips:
    try:
        r = requests.get('http://' + i + '/login.cgi', headers=headers, verify=False, timeout=2)
        print(r.text)
        response_from_iot[i] = r
    except:
        print("Exception with IP:" + i)

storeData(response_from_iot, 'response_from_iot.dat')
