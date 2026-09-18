import socket
import threading
from crypto_util import simulate_rsa_decrypt

# Standard server setup using local host and custom port
HOST = socket.gethostname()
PORT = 8888

# Keys generated for the server side
SERVER_PUB_KEY = "SERVER_RSA_PUB_123"
SERVER_PRIV_KEY = "SERVER_RSA_PRIV_123"

def handle_client(clientsocket, addr):
    print("New client connected from:", addr)
    
    session_key = ""
    algorithm = ""
    
    try:
        # Read the initial setup packet from client
        req = clientsocket.recv(2024)
        start_packet = req.decode("utf-8")
        print("Received setup request:", start_packet)
        
        # Clean up packet string and split components by comma
        clean_data = start_packet.replace("(", "").replace(")", "").split(",")
        
        # Check for valid protocol header (SS, RFMP)
        if clean_data[0] == "SS" and clean_data[1] == "RFMP":
            is_secured = clean_data[3]
            
            if is_secured == "0":
                # Unsecured mode requested: reply with standard CC
                cc_packet = "(CC)"
                clientsocket.send(cc_packet.encode("utf-8"))
                print("Unsecured connection setup complete.")
                
            elif is_secured == "1":
                # Secured mode requested: send server public key
                cc_packet = "(CC," + SERVER_PUB_KEY + ")"
                clientsocket.send(cc_packet.encode("utf-8"))
                
                # Receive client's encryption setup packet (EC)
                ec_req = clientsocket.recv(2024)
                ec_packet = ec_req.decode("utf-8")
                print("Received encryption details:", ec_packet)
                
                ec_data = ec_packet.replace("(", "").replace(")", "").split(",")
                algorithm = ec_data[1]
                encrypted_session_key = ec_data[2]
                
                # Decrypt the session key using server's private key
                session_key = simulate_rsa_decrypt(SERVER_PRIV_KEY, encrypted_session_key)
                print(f"Secured setup complete. Mode: {algorithm}, Key: {session_key}")

    except Exception as e:
        print("Error handling client setup:", e)
    finally:
        clientsocket.close()

def start_server():
    # Set up TCP socket, bind, and start listening
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((HOST, PORT))
    serversocket.listen(5)
    print(f"Server is up and listening on port {PORT}...")
    
    while True:
        clientsocket, addr = serversocket.accept()
        # Handle each client in a separate thread so multiple users can connect
        t = threading.Thread(target=handle_client, args=(clientsocket, addr))
        t.start()

if __name__ == "__main__":
    start_server()