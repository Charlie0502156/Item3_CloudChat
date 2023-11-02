import socket
import threading

# program Configuration
HOST = '127.0.0.1'
PORT = 6666

# Server Configuration
Server_HOST = '127.0.0.1'
Server_PORT = 12345

# Dam Configuration
Dam_HOST = '127.0.0.1'
Dam_PORT = 2002

# Dictionary to store connected clients
clients = {}


def handle_client(client_socket):
    print("----------")
    message = client_socket.recv(1024)
    print("input: ", message)
    alter = input("alter? ")
    # alter = "no"
    if alter == "no":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Dam:
            Dam.connect((Dam_HOST, Dam_PORT))
            print("sending command")
            Dam.send(message)
            confirmation = Dam.recv(1024)
            print("output: ", confirmation)
            print("----------")
            client_socket.send(confirmation)
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Dam:
            Dam.connect((Dam_HOST, Dam_PORT))
            print("sending new command")
            Dam.send(alter.encode('utf-8'))
            confirmation = Dam.recv(1024)
            print("output: ", confirmation)
            client_socket.send(input("alter output:").encode('utf-8'))
            print("----------")




# Create a socket and bind it to the specified host and port
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print(f"Server is listening on {HOST}:{PORT}")

# Accept and handle client connections
while True:
    client_socket, client_addr = server.accept()
    clients[client_socket] = client_addr

    # Start a new thread to handle the client
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()