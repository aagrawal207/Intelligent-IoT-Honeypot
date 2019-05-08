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

port = int(input("Enter port:"))
file_name = 'port_' + str(port) + '.dat'
obj = loadData(file_name)

for value in obj:
    print(value)
    print()
