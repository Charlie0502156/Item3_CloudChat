import socket
import hashlib
import threading

# Hashed
conf = {'24df1d0bcfb97d8116a78fee6d27f4cee4e335e6e71658ad30cb65577457c033': 'Dam at 0 percent outflow', 'eb3a875723d3ee12e630808d53f566c44ef2960facfff592ca88f7bb3ca8af13': 'Dam at 1 percent outflow', 'f71f607cb85364345481901d5b47a10697f945ed86a2c9573a60e161483ca1e8': 'Dam at 2 percent outflow', 'c90f46b800ef9a55df0857ffaca5c33bf27af54e9f176375ff6889494c473aef': 'Dam at 3 percent outflow', '9bf57acb0eb101726ea61ca4f8cfafc6991e527115e36c0f83fa8c125baaed05': 'Dam at 4 percent outflow', '3b9a3204176912573a8548d91fad65af9c23331d5085d1a38773e39f04130374': 'Dam at 5 percent outflow', '2e7d0037b48fd62ea044b8bd6c63553d25064df3278e92d259e811644eddd24c': 'Dam at 6 percent outflow', '4edb0667fb4c50281b7df091d30d1218c20e4b083537b73cf8f976e3d5f7d4d4': 'Dam at 7 percent outflow', '5745aa786a6a7dc4d444e3928dc7adeeac22e5fc72c32a36dac827bb15ef9534': 'Dam at 8 percent outflow', '812d6e8a66af67df61aea485602c80ec41157d4e20226a31ca755a0ece11ee1f': 'Dam at 9 percent outflow', '509df23b53fae3c188c2c0cc1bae49306c153c941c3c5f1109a1dd9bbbd0e269': 'Dam at 10 percent outflow', '652b1f0e0020f1100ab2068841df9a9fea3be2bc83001b921627dbe0ded61271': 'Dam at 11 percent outflow', '180d3b46d127ccac9e8a9e9a74248c8a90764c1aba21c4412718728c2db8e8f5': 'Dam at 12 percent outflow', '7c62815a63d38b2cebf517d99d2e99b7ab7f4e49dd1b8fbc3241b577bc6a44ec': 'Dam at 13 percent outflow', '013b8c2b39d2d4f1a58dc67f2a409c1a1498f8297170dcc7a1c86534c0b4423b': 'Dam at 14 percent outflow', 'd49c4e72b63223c740fbc2b9b99f6f17e2ac5e22caa13eca4d9626b8ceb5b4c5': 'Dam at 15 percent outflow', '430a79a4bb54ec098196b656d658736d1c52dbbee595e61190aa535e4999e4e2': 'Dam at 16 percent outflow', '39bb9d79ba2fad5c3df859199e6e1e1b2615a916cff54ade0978a720f915d023': 'Dam at 17 percent outflow', 'e7eea6b4bab480b6a22581511d8c7c94d0e172301d485a8df05eb802250ba800': 'Dam at 18 percent outflow', '00f77bfe030f74ece92b358cb42aac8f222ce61453382e31f038290cd3b8a402': 'Dam at 19 percent outflow', 'c8ffd262048a4ea0f71c93925b5daa26ac9f7d7255837a483dcf3ccfbfc7d610': 'Dam at 20 percent outflow', '0ddbf536240a75293e6c2c932480773b87a5f854d39415f1785ea172e1ac100f': 'Dam at 21 percent outflow', 'cdae8e4fe58ef125096aecf03f2becf8fb42421a1d65f4516ac6d8230e20539d': 'Dam at 22 percent outflow', '0dd701698f5aa28970e037a732b8473a6c3d92da736b79a1a8241b0e299f92cc': 'Dam at 23 percent outflow', 'fb3778b0a325e1253b5423edb0c47dc7fc910f5b8336964c91578e7687d8ce15': 'Dam at 24 percent outflow', '62e112dfcefe08f37e6283d46b8a65f1d80f7d472e4d1eb1b001553aaa833765': 'Dam at 25 percent outflow', '9ab5b00ff42e2fc328730409b1ef5d2244424bdae23b97fb13a06852e002df08': 'Dam at 26 percent outflow', '6965733c64f5c1832f6c922ee0b19d54066d681cf9ecef437d7139b33922938f': 'Dam at 27 percent outflow', '2b80ccd09e5a36a89f1e3cf9ce4caee61a2c7ce5070c1b042ab202faa92103bd': 'Dam at 28 percent outflow', 'a1f2a0981f57f2caa5725dc03482a851e9b540c357935bd23561fba981ca57f4': 'Dam at 29 percent outflow', 'c0eb9fef31e34a572daa5fe0595ed00b122b254ed7b17bb9b41e048196c04f75': 'Dam at 30 percent outflow', '660db493ff65f7c6001d2872bd95a1cfc00780f85f9174bfb8e577a8fd90098c': 'Dam at 31 percent outflow', '80afcee7bf34bd4b1356775b78f7a233ab2b3f0d028ba8ec4e2efed7b84b741a': 'Dam at 32 percent outflow', 'bbf53c82a1a30bfe49228cf828cb16833069a1ec2a0b1fbbbdefa243792e9339': 'Dam at 33 percent outflow', 'b6995dbef97cbdf66f6370576d0504397292349be7306d9b9c4c0b04c3c9a407': 'Dam at 34 percent outflow', '59119c9bb042c095bf38ecd5a78fbd87ac17e6d7f3111ca934bcbd05051b112d': 'Dam at 35 percent outflow', 'c403a86db3fcd0c39a474ba466f4b31b9c5fa01acb00177d68ba22d3845718c2': 'Dam at 36 percent outflow', '2e7f16a4f300a9e0b5eb0157c4f1836b137c89d8ffab99b73e9d8f73efcdba11': 'Dam at 37 percent outflow', 'fcd57d87fe2a4193f473b03abf096c49eb4fa55ce04982f5ef605d0a7c7c7a8b': 'Dam at 38 percent outflow', '1be4ea5c404f7846a2f76d48803173cfa8a052b914d54d2001968e5666c643d7': 'Dam at 39 percent outflow', 'd76cc36d252d18d55c90854de2277f72448f9fefe4c29a249175259dd508705a': 'Dam at 40 percent outflow', 'ec3c922d0e6670c2b8f9b8e38d71dbcef9d329e50591ca65d7b71ebdeb14e2b9': 'Dam at 41 percent outflow', '7656d06d9898ae9c267f1f391e655744e07a7732bc4e2376a076c0ec3ac471c6': 'Dam at 42 percent outflow', '8ff71da32068ab3b726bacd360bfb347fde742fd68fe079178ac85673aa6b209': 'Dam at 43 percent outflow', '8a52a011b1e0d75aac4714574e08f2c39e185010562dea9c79d5f198360635be': 'Dam at 44 percent outflow', 'a63beae9a11cd96cc38981bba4e3aa7532f3ed247b33d0b54e2da8a2cabaef67': 'Dam at 45 percent outflow', '80783d5fa204bb55c769da78e98e5b4851fe478ab616772675ea3b9adcb77e6a': 'Dam at 46 percent outflow', 'c17ac28be155168c10afadde7e21d78db24c33704c2720acaf806992e02a5bde': 'Dam at 47 percent outflow', '629353d8438686ea622d315a163ce5c59077662cf760522f561283de6ae126a7': 'Dam at 48 percent outflow', '948d1406927d15c3332a2e3c187cefb75f23f543b82b6a4b8dc27deddcdf7146': 'Dam at 49 percent outflow', '613df827aa608f621c02145dfbc5b672b6b5acec5a515ec4aa40326be9e9842b': 'Dam at 50 percent outflow', '3e79299f43d0d6abbe1775dfd52511a508b1cb9987d0b0163c1d736a2236ae48': 'Dam at 51 percent outflow', '80947085951ed0fd8d6826a72f6a374db0aefa6094ecc99f269a3d1b9df4e051': 'Dam at 52 percent outflow', '93e5456c18f82c9f5cb9271b490330e903b970798627497b0763dd5325e70966': 'Dam at 53 percent outflow', 'a537222412d74d428aca03917db32ca69132f337538a08c224445733e23b6a29': 'Dam at 54 percent outflow', 'e7c2f0e01cded76e33abb67de48124189262678af23b2bef51f6fa0f0af60912': 'Dam at 55 percent outflow', 'aed18927f64c41401c6424063bb2ece98b98e9fcd593db2578833f0e17c3cfd3': 'Dam at 56 percent outflow', '60808b43dc9973dc4cf22e4b8988bb55e352341d837c3ba62cda02940acc1adb': 'Dam at 57 percent outflow', 'b4dd67f25b90fb520852e98221fccfa43b1101eed0e12fdb00bf57dd8cc1bdcb': 'Dam at 58 percent outflow', '8cc2398ec68633cf2d07b39495840d881ea7dcdccf03da5835bbe9f324a0aee7': 'Dam at 59 percent outflow', '54b3ee985cf84f0e5b610756e261d97e1612fb976d0cf7f0726020a1cd7d3e4a': 'Dam at 60 percent outflow', '20082fcf578cb117e3829059701594af7aae4b7cb90569a9011c534a04e6aa34': 'Dam at 61 percent outflow', '076b97d8340e6d8f5de9d3da287997a6f95a4250418adb5505864eec1e56783f': 'Dam at 62 percent outflow', '2f145f632abe43ab8fd00f69578489c0070670c6c94db03601d5142eeeed903f': 'Dam at 63 percent outflow', '49fbb8607861b822d50bd2e3f8abc461ce602273797ab6dcbd357d91197b12d3': 'Dam at 64 percent outflow', '6fb01e5ed03ed4bd230cb3ad551a5f40b4266dc1b34dc356c4498ad91b9b45b5': 'Dam at 65 percent outflow', '46c239686c50e4488e54ffccda6e7616949f06b04e333a6ac3898009e365ec5e': 'Dam at 66 percent outflow', '82f3112454be3b00092e831dd1137795bd84eac445ee1535041fe01a0b7538a3': 'Dam at 67 percent outflow', '99895d78f4560676bc4986cc1afbf2f80e02fe4f397704060d13d2e0b8a62333': 'Dam at 68 percent outflow', 'ec2e763bd83f144941313cc7309ed35b11179f43b0ce3470ff81d60ab47841e2': 'Dam at 69 percent outflow', '0725a0506b4abdd24dab4975ff0b6e84b063a8b0710108205c707e95372f7828': 'Dam at 70 percent outflow', 'e4b3014901384e29a0b161eccc5a4784fe6279c215244da29cc83b26401268a0': 'Dam at 71 percent outflow', '05609c915552eab11feee75152ee174663db832f1a1fa3eb601ea2413c83290b': 'Dam at 72 percent outflow', '032ecd8cfe29e76e7edb2ba1d8975c27fb170452d2297d87b33ee66f5455fbbf': 'Dam at 73 percent outflow', 'f0a0ad5f6b56750269e4af3979fafae7671ed6e141a7760690fbf528722bdf51': 'Dam at 74 percent outflow', 'fe2fbc4cfb817a9c00c45009c72e4556bfd6ea37a624056793367c1fbb365710': 'Dam at 75 percent outflow', 'beebd939f2a35fe531f6f7a047396e3c8285fbf90acaf8b9daaf1c40fb5ba776': 'Dam at 76 percent outflow', '19827d0e351e82672648c62f2e974c0bfd66ffb9589b0a5b2efed7d41aa7925d': 'Dam at 77 percent outflow', 'a9d84ea7304a73d14c1e8390cf85a06dae667f8647e338d036e5e000b20423ca': 'Dam at 78 percent outflow', 'cf481b4c03e6be856c1995c01a35979c62bf5faef298de6dbda9247d8739e58d': 'Dam at 79 percent outflow', '4adfe144ee86f0b655dab5d30ab7d59d8b307f914035d3aaab9e1aac936e8232': 'Dam at 80 percent outflow', '31a7aa33778cbba3ff8774416acf7ca476b010b688166151eb5b45dd4ae086eb': 'Dam at 81 percent outflow', 'e95fb82ae421302988e30121ec5ca3a8587e9e34096cf1a27804574de639df94': 'Dam at 82 percent outflow', '02ef72005092d06c1da162a5d2638a7af25057105271a298d07337bf26cd7977': 'Dam at 83 percent outflow', 'de471584ea6a39ac4d04de6bda250e2f2d2497551f2e3d34e0927ee14fb5a332': 'Dam at 84 percent outflow', 'c230a8b28e30f47a3cd205f00069a0a87ba5edbf3a8305908cad844b84f10b9b': 'Dam at 85 percent outflow', '9e3dccbac01a75eab5acb7cc4735621c731bfe6111b4bb654219aeed27e4ab25': 'Dam at 86 percent outflow', '7a87a9867d36b4a50d45332ee4b0bb6f292eb2b8c17a2a8a2542860726e10091': 'Dam at 87 percent outflow', 'd28a437c69d51f4d895d5ddc6a846b444d9efc13b8d245322dc8d204105e1936': 'Dam at 88 percent outflow', 'edbdf1dcc189de2bcd809ddd2ca1b8569a4afab12e7f287f28994a505b6d0be9': 'Dam at 89 percent outflow', '3eb573c882392e759a67792ee6c9a91d28f4f02236f6dbd3c4d789d4070eff19': 'Dam at 90 percent outflow', 'd61bffb35913d7590cec6f55956cca1a1ab6aad9c288754d88a43a0d892619aa': 'Dam at 91 percent outflow', '548765aface3977bbb8428f35852ea2dea97c8547b8283277015d334c50a34b1': 'Dam at 92 percent outflow', '9aeece403d9eea8fdb6f11480113c4c83505a361297db0026b2a72e8cbdd111e': 'Dam at 93 percent outflow', '109ae5dc3f43febb72236659186a547e1ae8578c4049085e7bccd6becc8a94f5': 'Dam at 94 percent outflow', 'b2affde2357ae3c4b6ef36006342d1287a1d541d7c519169e5284af29fa6e9a5': 'Dam at 95 percent outflow', '1b9d90b03e693d35afa727211095153cd3b25512cc3bfe7f281faf0ffa7d2d1b': 'Dam at 96 percent outflow', '08397ce543c234c93da795d06356dcd52ca7283c3ff16a01943eff0259fa4d28': 'Dam at 97 percent outflow', 'efcad845c82bfdcf7d1b7599c4a2699992a04c2d4b4440f65a43150120f2d580': 'Dam at 98 percent outflow', '2c33464282fa925990c3288fbee5f07e7b46f5e9aa122b0db2369ad5ec17add5': 'Dam at 99 percent outflow', 'ba055eb5c7927dc573ca0da8c135999d04119258c8bd76b0516a3ec559bfcd6e': 'Dam at 100 percent outflow'}

# Server Configuration
HOST = '127.0.0.1'
PORT = 12345
PASSWORD = "password"

# Dictionary to store connected clients
clients = {}
remote_server = None

# Function to hash a message
def hash_message(message):
    print("Hashing: ", message)
    sha256 = hashlib.sha256()
    sha256.update(message.encode('utf-8'))
    return sha256.hexdigest()

# Function to handle a client's connection
def quit_server(client_socket):
    del clients[client_socket]
    client_socket.send("You have left the chat.".encode('utf-8'))
    client_socket.close()
    recieving_messages = False
    return recieving_messages


def send_message_to_dam(client_socket, message):
    Dam_HOST = "127.0.0.1"  # The server's hostname or IP address
    Dam_PORT = 6666  # The port used by the server
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as Dam:
        Dam.connect((Dam_HOST, Dam_PORT))
        # while True:
        #input("ready to send commands: ")
        print("sending command")
        # message = message.encode('utf-8')
        message = hash_message(message)
        message = message.encode('utf-8')
        print("output: ", message)
        Dam.send(message); #message.encode('utf-8')
        wind = Dam.recv(1024)
        print("input: ", wind)
        wind = wind.decode('utf-8')
        confirmation = conf[wind]
        print("decoded: ", confirmation)
        client_socket.send(confirmation.encode('utf-8'))
        # break 
    return confirmation

def auth_user_to_server(client_socket):
    client_socket.send("Enter the password: ".encode('utf-8'))
    password_attempt = client_socket.recv(1024).decode('utf-8')
    password_attempt = password_attempt.strip()
    print(password_attempt)

    if password_attempt != PASSWORD:
        client_socket.send("Incorrect password. Closing connection.".encode('utf-8'))
        client_socket.close()
        return hashed_message

    client_socket.send("Authentication successful. You are connected.\n".encode('utf-8'))
    return client_socket
    

def handle_client(client_socket):
    try:
        # # Request password from the client
        client_socket = auth_user_to_server(client_socket)
        recieving_messages = True
        while recieving_messages:
            # Receive a message from the client
            message = None
            message = client_socket.recv(1024).decode('utf-8')
            print("inputed from client: ", message)
            # Check for commands
            if message.startswith("/"):
                if message == "/quit":
                    recieving_messages = quit_server(client_socket)
                elif message.startswith("/command"):
                    confirmation = send_message_to_dam(client_socket, message)
                    client_socket.send(confirmation.encode('utf-8'))
            else:
                # Hash and broadcast the message to other clients
                client_socket.send("Invalid command")
    except Exception as e:
        print(f"Error handling enp4s0client: {e}")
        del clients[client_socket]
        client_socket.close()

# Function to broadcast a message to all connected clients except the sender
def broadcast(message, sender_socket):
    for client_socket in clients:
        if client_socket != sender_socket:
            try:
                client_socket.send(message.encode('utf-8'))
            except Exception as e:
                print(f"Error broadcasting message: {e}")
                client_socket.close()
                del clients[client_socket]

finding_server = True
while finding_server:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((HOST, PORT))
        server.listen(5)
        finding_server = False
    except:
        PORT += 1
        print(f"PORT BUSY --> NEW PORT: {PORT}")

# Create a socket and bind it to the specified host and port
# server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server.bind((HOST, PORT))
# server.listen(5)

print(f"Server is listening on {HOST}:{PORT}")

# Accept and handle client connections


while True:
    client_socket, client_addr = server.accept()
    clients[client_socket] = client_addr

    # Start a new thread to handle the client
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()

    
