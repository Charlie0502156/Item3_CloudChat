import socket
from random import choice, randint
from time import sleep
import hashlib

def hash_message(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode('utf-8'))
    return sha256.hexdigest()

# HOST = "127.0.0.1"  # The server's hostname or IP address
# PORT = 12346  # The port used by the server

# e.g  /command open 30, /command set 50

operator = [
    # 'open',
    # 'close', 
    'set'
]

def hash_message(message):
    sha256 = hashlib.sha256()
    sha256.update(message.encode('utf-8'))
    return sha256.hexdigest()

def connect(HOST, PORT):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        data = s.recv(1024)

        print(data.decode('utf-8'))
        psw = input("")
        s.sendall(psw.encode('utf-8'))
        confirmation = s.recv(1024).decode('utf-8')
        print(confirmation)
        # rand = str(randint(0,100))
        # cmd = choice(operator)#input("ready to send commands: ")
        message = input("Input:")
        print("sending:",message)
        s.sendall(message.encode('utf-8'))
        confirmation = s.recv(1024).decode('utf-8')
        print(confirmation)

if __name__ == "__main__":
    import sys
    HOST = "127.0.0.1" 
    # args = sys.argv[1:]
    # PORT = int(args[0])
    # # print(HOST, PORT)
    PORT = 12345
    connect(HOST, PORT)

