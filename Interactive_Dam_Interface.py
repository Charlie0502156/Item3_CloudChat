import socket
import hashlib
import threading

cmds = {'147448f68423a333e2ebeb625dd26643205d6ecb6aeb0ef842ff9ca2621a1162': '/command set 0', '49578b65a9e22e7c912f5a0e877687e0b2e3982b0c7e3c30149f87df900e7ca2': '/command set 1', '993f38b40e1889fbdd2c29b180ad6d2ecfdb555bffbfa84ecbe2f4cc4abdf026': '/command set 2', '5b8d1464c023ceaf53ceaf16c67bdcf141ea0e9e3603ea5ce0a081c61ce5e559': '/command set 3', '968323a432451c87151d1e8d2f0004cf63dc0b99c4e85c21d7958312f4144b82': '/command set 4', 'aee408d4c9a3ddd7e89a1e063568c82b559c8a3461e8c81007051212a17466d6': '/command set 5', 'a72010e45e35a4740ca25922480d73a986cc54f6f80140334c897a344dd52364': '/command set 6', '8299e16e148d280eb7676cf0c88b1c71a12caa54c44cfa15675442ba6c5f2667': '/command set 7', '1fdc63d9bd738b57831615c210ca80564a18beb77faae5869a238121f48f1443': '/command set 8', '065179506ebb3b0875a18ba5032b6d7da0a6fa436da7d78cf74f37b4715f1670': '/command set 9', '0ac5900da10a10d768a2c51eeafd494a3ed61502b4045ad6f306e9c396fa4458': '/command set 10', '019f32048a29f7c35ada1eefde20fba767c8000aa9bd32de147d550de80ea72b': '/command set 11', '0ea82b6947b2db29b0f9ebf27447f57dd7c79f3579ec66a79fe70c345f1e99cb': '/command set 12', '27203fb760ea7657c1451661dedbfd99f177ff21fc788ae25cc9a850f5985958': '/command set 13', '4f8f1b40b5f6a01542bc83f83a1c9211151fc5c2345ed3a83564a52d2445da55': '/command set 14', '906a9858f7e210ccbe4051ad4bb685982ee27ce30f98f30e2eb75a251cf8af30': '/command set 15', '6c50ae38e8f58a2c865236bedfc6af9c2a0c5b9a5c0cdeb840506bab71dca79b': '/command set 16', 'aa5c7de6cfd8d2e829f2ff4d96ed65c3353bb4c6b1b0915b9a43ca4148bfc165': '/command set 17', 'a2ae0aca409f5d51f2ffd7735e2548d66397dc01fec8f9c48b87f694e0466f6f': '/command set 18', '9abc757dbce70f4bf46283de531f386360ccd982e5cf7f751536bb64d3465bb4': '/command set 19', '04dcf492685a3978bbaff019fab4a93c1c68c320ee34172c72ec2cb660e0eb79': '/command set 20', '369da932ab14caf390b061ffc0966ea253ccfa7833ca3103315faed4afc2c038': '/command set 21', '53ddaf4ecfe132ade1af1e3f043a4bbd51197f43ad4766877a11962309f214ac': '/command set 22', '5c33e8124cf27e88b658d92c79bae70973a974448968a112997b95c101df0a3b': '/command set 23', '7ed0dad3f158eb287c7c010b3e2d9d59d8b3c0b16444dbe884f11ed46358dcac': '/command set 24', 'cf003f8e0d26a957ee65df91394b93d2f399e15ae2dbf8f1c29cc125cd919008': '/command set 25', 'e125202b1219d6269d89ee32960b4d978345dc0febaa922be2360a6b20ddce6c': '/command set 26', '4cbb925c5a36957a367a5f7bb8352c15bf452c75197df5a1522789ab063c74d4': '/command set 27', 'a4b3f3517b993d57330a8cd482ac75aa20b3a5d74b105f7a739375c5f5aaf01c': '/command set 28', 'afd149eac71fe6df40a0e1d78993779bbab77d015b32c3a3aff4c292b2acdd90': '/command set 29', '7283692614bad0653c7ee2b617eae4ddacd7abef360a9695b5a18323ab352d1a': '/command set 30', '23d8e4d21b6d07e322ccdd0265eb82f6378b9c14d30d635e311a77f2ec9bd1c6': '/command set 31', '8afbbf2152a56e82d04d7069e97d6e72a3663045c5072ee86f4b2bc4ec0405c7': '/command set 32', '0462e96ca9a47dd1733af1cbccba7a641358d236f49f8b59fa91ee7b7481fbad': '/command set 33', '5ea1c90d44d4b1f109c64f8022fd8b0d2bb12034af6c34e24b41555371a7d3f5': '/command set 34', 'c80df0d15409d86ca8b763e512889c66a42794e3e2b95c65ad22204dbb33cab5': '/command set 35', 'ce2f5d65a2b884a38b8134b477d1185923f80185db5c6717777c233c910c4054': '/command set 36', '8500166f668c2380b88635c4ae203ac04d49ec9ae0d6758d1cdb452a5e14a089': '/command set 37', 'ffae375d977986ca76bc22f7053718077ebe8fa4eba0a03e5c8764c3c87b7909': '/command set 38', '6720d476978c4380eed0903f15dbc9b68dc2342ee4224a55d279d96dfad06566': '/command set 39', '47e72488361b015874f4e2076dddf051f6abe401cc593ca351c9c2da86745f31': '/command set 40', '08a3ce890835f6f8e3bac8962900afb4d8412bbe17020e7f49c0071fecb12eb4': '/command set 41', '3cb74d9d7827dc0bb077a65c438e5a47ec0409c2a57688a5c31f03e1414ae57d': '/command set 42', '6564021918b2d705ba752923922e5d01d571119f5c3809ca884a92c06c015351': '/command set 43', '0f52796f4662b94548ba797a76e095cf61a89a2c06fb153af559148325078bb9': '/command set 44', '7d3a37f1b71795ab9b78500e9d1f82927f17ca93ff41a93d56d7696f03c34a31': '/command set 45', '811d102200aee9605eb948f79400fc8c7995a36c6cdae9f810663c5eaa4277a0': '/command set 46', '52d828aa04827a1681acf6ee063c1659bdd96e045e8ac6f36941b0959a6a7ba7': '/command set 47', 'e9c85b2cb9d6c88fd29b370078efadacff7f72a6843c6f2f1e0561b9691ce458': '/command set 48', 'cfa90c4e449dd82f20fd588a21c5f6852073fe6cf58c4c9c7e1832062de195e9': '/command set 49', '337fe091fe7a9992dd455132b02ddbf9289bed7d96391a0709024543575139c7': '/command set 50', 'da9327c6595184811983dfa71f3f2d5c2e593a0faeac656490f1cf93c436268d': '/command set 51', '89f56e2007839f975311d81f17bc299649cbe8742bd4a176b004b1e8536ee7ab': '/command set 52', '1253940fdddc65e7caecd4b4f193c5fb7bbcc74de936bb61ca985c71c4433ec0': '/command set 53', 'b3e25e8e3ac2cfbf764b4f66a821dbded56598aef11ffcaa2afc23818d620e45': '/command set 54', '1fdd4ffa5b75f852753d1dbda60e0eb0e7f3c3cb50dd4a6d094049a0474d974e': '/command set 55', '921e0d088c97d58e2092872a349bde85be26d15b06f74d0ee20e447622a26a20': '/command set 56', 'f275fac3e476bd97feda91da96dafc1a7e7a014ac8b797366f68111404fdf042': '/command set 57', '81d8582353abb227861b4b3f99d0a027993f67f65cd664f59e88e26b09b22c44': '/command set 58', 'e30ffc50a08ed2b8dd2c81af47de9f03b38f04e39f210c987ce25c3f7b326573': '/command set 59', '8656fa3bc8907a29c4ac1cc67807f514f9c29f80d5f5d617c215cf4a37941174': '/command set 60', '473f602f18099578994ab2b212b1431b5a6e1842bdac59fc4f514e36958e8133': '/command set 61', 'c6086fda0487b364b28c9c1e9d661e2580379142d1684f97326aeca361510980': '/command set 62', '89af96904781aa499415a3ad1ee3428a8654b9a68f14c85fd7d2f1c1597ba520': '/command set 63', '50d2fa797331b13dd2dd811f37e0f59a952238f2083f2370e7fe44288f51e1df': '/command set 64', 'd9e02a46165bf9af388a2acf6ba975f369af716607888fe6ad2565e280fb8e43': '/command set 65', '7e7a6f85f56012cfc711225e82e79da0a7df64f5864da5d8615d635b3c7de8af': '/command set 66', '12a2170cbfde3b08e269cbda31988ff8e723bb0d92242491a5cf03e195f12212': '/command set 67', '3cb0908932b4fe3c3f64b625994f64756e6ca2a084f70045b79303e169b5cc05': '/command set 68', 'fec2f88bb005dc1de49897335eb44e00c4ff724d76ecc21d2575f88ff9ecf32e': '/command set 69', 'e4cd903d523f7f24186da0ea08547abde23291d77fd1e7843306eb7f7975e741': '/command set 70', 'f87669e52d058fdcc5db8223ad46638631a30de698955acffdedba60cff0b9f2': '/command set 71', 'd043d8fd277ceb60e50c90cbef691e7f84c8ecc470ffdb178a748acbd2d0b7f2': '/command set 72', '7e21986ddf54a147afedb65eb41bd42f2a491afedad7e83019cc99dc48170b23': '/command set 73', '46314e442a44bf8b599c8b5da06400eb1ac9219c1d2ea057cc43901ec0310be8': '/command set 74', 'b7412d23f2ab993ba80f37bd526508b515c8edda6d320c09d0e5df13865b5a5c': '/command set 75', 'b61c04a8b3b50176895fd613f547d2f4492cf30f0af5d8c32f00ee6aed76d10c': '/command set 76', '55a75c02af7771ae68763831e75d5f5b95c2316dea6dda5b6ffc8cf3535a3d01': '/command set 77', '4b5b8f06ec9b56cd9d8c537d9c73d767c13aad30e45598ba1ba2a427404a1eb2': '/command set 78', '8944ceef38cb1a3c3e2a965d8c954f762083f9036ec7391016b654977d8f8f91': '/command set 79', '6cee530fda1463797526a42648799aca323999346c9c98492caa4ce206a5c0d0': '/command set 80', 'cd03156bc0e46aa40f040866e3f93c757ac8d668504acfee368624cb7326cf5c': '/command set 81', '29501f6777719aa5ebe120ebc3822caf125137b5d6a20da430b8e9fb49acc212': '/command set 82', 'df10a952da89f9094fe9ec2a20c89ce9298e23869a059633abe9826fe0426be5': '/command set 83', 'dbf8edf61706d13996d8430d9390a184013796d2e8d76a81b2ce7e633f1ef345': '/command set 84', '70a783ee3131c97800361483c75372d3c6d28c177ded1ce14e1b9251a88d1409': '/command set 85', '621116f43cd67cdbd31d1ae988aa0a36112945918a7c58ef05cbdd26edc292e6': '/command set 86', '6e94abede9fafd7348de9e692556d5d26c9c6bcb5f37050b74e33b29cf15a00a': '/command set 87', '4fa1af1e193b7219a341dfa60ad20eae8b7d4e627286e621f215bc2e7068d7cc': '/command set 88', 'a7649b5c2a9c3d9574e2eda813d17ae5cc7448f6cb932f909a14633690bbbd23': '/command set 89', '3547c0fc4b7616ac66c9cf824b7afe9c73755f952c9c75d92d06d374af8ac553': '/command set 90', '6bd26480e23b70789a06f54666c51feb4ead3c8051dca06d967fbc11c60713a9': '/command set 91', 'ced499343c6a700368fd6250dc7752f471d29280ed7ca95b0a345eb807a3a5d2': '/command set 92', '607c8a18ad7df22212e48c7ebc2a6af5a6137246679c9cca4158755f68ccd6d7': '/command set 93', '9dfaba480499872fa2a70e7329e9963f7475187e0bde66ad9e6a6d3020dbfab6': '/command set 94', '30c42326241d1f5162c9d22a58a952bbdb735f16a1a705e4fbd8cd6224c49d0f': '/command set 95', '376913edef7e56c29c4014a20467e8636c62d6f817ca067710e32e0375c40ccc': '/command set 96', 'aea92c663e1a61ce159d5128104685a0f30723d45a47e55b22f6735d282ac96f': '/command set 97', '580ae18ebaceb1244097aead512781d408762da0ef405134c1ed808027b49728': '/command set 98', '676163bfc695ad9541035706380d8850a3acb95cf9f9dddebf2b31777a5cbf69': '/command set 99', '4169bdcc3f05d16102d8826f41d8d15914f274a25043407640eade6fcf3f226c': '/command set 100'}


# Server Configuration
HOST = '127.0.0.1'
PORT = 2002

# Dictionary to store connected clients
clients = {}

# Function to hash a message
def hash_message(message):
    print("HASHING: ", message)
    sha256 = hashlib.sha256()
    sha256.update(message.encode('utf-8'))
    return sha256.hexdigest()

# Function to handle a client's connection
def handle_client(client_socket):

    # Receive a message from the client
    message = client_socket.recv(1024).decode('utf-8')
    # command = message.split()

    # if str(command[1]) == 'open':
    #     x = 1
    #     a = 1

    # elif str(command[1]) == 'close':
    #     x = -1
    #     a = 1

    # if str(command[1]) == 'set':
    #     x = 1
    #     a = 0
    # else:
    #     print('error')

    # result = b*a + x*int(command[2])
    # confirmation = f"Dam at {result}% outflow"
    print("input: ", message)
    x = cmds[message].split()
    print(x)

    result = x[2]
    confirmation = f"Dam at {result} percent outflow"
    confirmation = hash_message(confirmation)
    client_socket.send(confirmation.encode('utf-8'))
    print("output: ", confirmation)

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


print(f"Server is listening on {HOST}:{PORT}")

# Accept and handle client connections
while True:
    client_socket, client_addr = server.accept()
    clients[client_socket] = client_addr

    # Start a new thread to handle the client
    client_thread = threading.Thread(target=handle_client, args=(client_socket,))
    client_thread.start()