import socket
from crypto_util import simulate_rsa_encrypt

HOST = socket.gethostname()
PORT = 8888

CLIENT_PUB_KEY = "CLIENT_RSA_PUB_456"

def run_client():
    # Connect to the server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))
    
    print("Select Security Option:")
    print("0: Unsecured")
    print("1: Secured")
    sec_choice = input("Your choice (0/1): ")
    
    # Send Start Packet: (SS,RFMP,v1.0,choice)
    start_packet = "(SS,RFMP,v1.0," + sec_choice + ")"
    s.send(start_packet.encode("utf-8"))
    
    # Wait for response from server
    response = s.recv(2024).decode("utf-8")
    print("Server replied:", response)
    
    if sec_choice == "1":
        # Extract server public key from response tuple
        cc_data = response.replace("(", "").replace(")", "").split(",")
        server_pub_key = cc_data[1]
        
        alg_choice = input("Select Encryption (Caesar/AES): ")
        raw_key = input("Enter Session Key: ")
        
        # Encrypt key using server's public key before sending
        enc_session_key = simulate_rsa_encrypt(server_pub_key, raw_key)
        
        # Send Encryption Packet: (EC,Alg,EncryptedKey,PubKey)
        ec_packet = "(EC," + alg_choice + "," + enc_session_key + "," + CLIENT_PUB_KEY + ")"
        s.send(ec_packet.encode("utf-8"))
        print("Encrypted session setup finished.")
    else:
        print("Unsecured session setup finished.")

    s.close()

if __name__ == "__main__":
    run_client()