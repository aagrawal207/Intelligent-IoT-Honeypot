import socket
import random
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


s = socket.socket()
host = socket.gethostname()
port = int(input("Enter port number:"))
s.bind((host, port))

# request_set = set()
request_set = loadData('port_' + str(port) + '.dat')

login_cgi = loadData('response_from_iot.dat')

s.listen(5)
print("Server started:")
try:
    while True:
       c, addr = s.accept()
       print('Got connection from', addr)
       msg_recived = c.recv(16384)
       print(msg_recived)
       request_set.add(msg_recived)
       if b'login.cgi' in msg_recived:
          print('hello')
          address, response = random.choice(list(login_cgi.items()))
          print(address, response)
          #c.send(b'Thank you for connecting')
          c.send(response.content)
       else:
          c.send(b'Thank you for connecting')
       #c.send(b'Thank you for connecting')
       c.close()
except KeyboardInterrupt:
    print("Program interrupted, storing data and exiting.")

storeData(request_set, 'port_' + str(port) + '.dat')
