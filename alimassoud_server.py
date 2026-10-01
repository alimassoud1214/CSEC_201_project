import socket
import threading
import os
import shutil
import subprocess
from crypto_util import simulate_rsa_decrypt

# Bind to 0.0.0.0 so clients on Windows and local networks can connect cleanly
HOST = "127.0.0.1"
PORT = 8888

# RSA key stubs used during setup phase
SERVER_PUB_KEY = "SERVER_RSA_PUB_123"
SERVER_PRIV_KEY = "SERVER_RSA_PRIV_123"

# Rubric-compliant Error Codes (EE,ErrorCode,Description)
ERR_FILE_NOT_FOUND = "1"
ERR_MISSING_ARG = "2"
ERR_UNKNOWN_CMD = "3"
ERR_OP_FAILED = "4"

def handle_client(clientsocket, addr):
    print("Got a connection from %s" % str(addr))
    
    current_dir = os.getcwd()
    session_key = ""
    algorithm = ""
    
    try:
        # Setup phase
        req = clientsocket.recv(2024).decode("utf-8")
        print("Received setup packet:", req)
        
        clean_ss = req.replace("(", "").replace(")", "").split(",")
        
        if clean_ss[0] == "SS" and clean_ss[1] == "RFMP":
            is_secured = clean_ss[3]
            
            if is_secured == "0":
                clientsocket.send("(CC)".encode("utf-8"))
                
            elif is_secured == "1":
                cc_packet = "(CC," + SERVER_PUB_KEY + ")"
                clientsocket.send(cc_packet.encode("utf-8"))
                
                # Timeout prevents server from freezing if client skips sending EC packet
                clientsocket.settimeout(1.0)
                try:
                    ec_req = clientsocket.recv(2024).decode("utf-8")
                    if ec_req and ec_req.startswith("(EC,"):
                        clean_ec = ec_req.replace("(", "").replace(")", "").split(",")
                        if len(clean_ec) >= 3:
                            algorithm = clean_ec[1]
                            encrypted_key = clean_ec[2]
                            session_key = simulate_rsa_decrypt(SERVER_PRIV_KEY, encrypted_key)
                except socket.timeout:
                    print("No EC packet received from client; continuing session.")
                finally:
                    clientsocket.settimeout(None) # Clear timeout for normal operation

        # Operation phase
        while True:
            cmd_data = clientsocket.recv(2024).decode("utf-8")
            if not cmd_data:
                break
                
            msg = cmd_data.strip()
            print("Received command:", msg)

            # Strip (CM,prompt,...) or (CM,action,...) envelope sent by client
            if msg.startswith("(CM,"):
                msg = msg[4:-1]
                parts = msg.split(",", 1)

                if len(parts) == 2:
                    command_type = parts[0]
                    arguments = parts[1]

                    if command_type.lower() in ["openread", "openwrite"]:
                        msg = command_type + " " + arguments
                    else:
                        msg = arguments

            # Closing phase
            if msg == "(End)" or msg == "exit" or msg == "close" or msg == "quit":
                clientsocket.send("(SC,Session Closed)".encode("utf-8"))
                print("Client disconnected.")
                break

            tokens = msg.split()
            if not tokens:
                continue
                
            cmd = tokens[0].lower()

            # Directory and file commands
            if cmd == "mkdir":
                if len(tokens) > 1:
                    folder = tokens[1]
                    try:
                        os.mkdir(os.path.join(current_dir, folder))
                        clientsocket.send(f"(SC,Directory '{folder}' created)".encode("utf-8"))
                    except Exception as e:
                        clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Missing directory name)".encode("utf-8"))

            elif cmd == "cd":
                if len(tokens) > 1:
                    target = tokens[1]
                    new_path = os.path.abspath(os.path.join(current_dir, target))
                    if os.path.exists(new_path) and os.path.isdir(new_path):
                        current_dir = new_path
                        clientsocket.send(f"(SC,Changed directory to {current_dir})".encode("utf-8"))
                    else:
                        clientsocket.send(f"(EE,{ERR_FILE_NOT_FOUND},Directory does not exist)".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Missing target directory)".encode("utf-8"))

            elif cmd == "rmdir" or cmd == "rd":
                if len(tokens) > 1:
                    folder = tokens[1]
                    try:
                        os.rmdir(os.path.join(current_dir, folder))
                        clientsocket.send(f"(SC,Directory '{folder}' removed)".encode("utf-8"))
                    except Exception as e:
                        clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Missing directory name)".encode("utf-8"))

            elif cmd == "del":
                if len(tokens) > 1:
                    filename = tokens[1]
                    try:
                        os.remove(os.path.join(current_dir, filename))
                        clientsocket.send(f"(SC,File '{filename}' deleted)".encode("utf-8"))
                    except Exception as e:
                        clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Missing filename)".encode("utf-8"))

            elif cmd == "ren":
                if len(tokens) > 2:
                    old_name, new_name = tokens[1], tokens[2]
                    try:
                        os.rename(os.path.join(current_dir, old_name), os.path.join(current_dir, new_name))
                        clientsocket.send(f"(SC,Renamed '{old_name}' to '{new_name}')".encode("utf-8"))
                    except Exception as e:
                        clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Usage: ren <old_name> <new_name>)".encode("utf-8"))

            # Built-in system commands
            elif cmd == "ls" or cmd == "dir":
                try:
                    files = os.listdir(current_dir)
                    file_list = ", ".join(files) if files else "Directory empty"
                    clientsocket.send(f"(SC,Files: {file_list})".encode("utf-8"))
                except Exception as e:
                    clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))

            elif cmd == "pwd":
                clientsocket.send(f"(SC,{current_dir})".encode("utf-8"))

            elif cmd == "whoami":
                clientsocket.send("(SC,User: RFMP_Client)".encode("utf-8"))

            # File I/O operations
            elif cmd == "openread":
                if len(tokens) > 1:
                    filename = tokens[1]
                    file_path = os.path.join(current_dir, filename)
                    if os.path.exists(file_path):
                        try:
                            file = open(file_path, "r")
                            content = file.read()
                            file.close()
                            clientsocket.send(f"(DP,{content})".encode("utf-8"))
                        except Exception as e:
                            clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))
                    else:
                        clientsocket.send(f"(EE,{ERR_FILE_NOT_FOUND},File not found)".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Missing filename)".encode("utf-8"))

            elif cmd == "openwrite":
                if len(tokens) > 1:
                    filename = tokens[1]
                    file_path = os.path.join(current_dir, filename)
                    
                    clientsocket.send(f"(SC,Ready to receive write data for {filename})".encode("utf-8"))
                    dp_packet = clientsocket.recv(2024).decode("utf-8")
                    
                    text_data = dp_packet
                    if dp_packet.startswith("(DP,"):
                        text_data = dp_packet[4:-1]
                        
                    try:
                        file = open(file_path, "a")
                        file.write(text_data + "\n")
                        file.close()
                        clientsocket.send(f"(SC,Successfully written to {filename})".encode("utf-8"))
                    except Exception as e:
                        clientsocket.send(f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8"))
                else:
                    clientsocket.send(f"(EE,{ERR_MISSING_ARG},Missing filename)".encode("utf-8"))

            # Fallback for system commands
            else:
                try:
                    res = subprocess.run(
                        msg, 
                        shell=True, 
                        cwd=current_dir, 
                        capture_output=True, 
                        text=True, 
                        stdin=subprocess.DEVNULL
                    )
                    out = (res.stdout + res.stderr).strip()
                    if res.returncode == 0:
                        clientsocket.send(f"(SC,{out})".encode("utf-8"))
                    else:
                        clientsocket.send(f"(EE,{ERR_UNKNOWN_CMD},{out if out else 'Unknown command'})".encode("utf-8"))
                except Exception as e:
                    clientsocket.send(f"(EE,{ERR_UNKNOWN_CMD},{str(e)})".encode("utf-8"))

    except Exception as e:
        print("Error handling client:", e)
    finally:
        clientsocket.close()

def start_server():
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((HOST, PORT))
    serversocket.listen(5)
    print("Server is listening on port", PORT)
    
    while True:
        clientsocket, addr = serversocket.accept()
        t = threading.Thread(target=handle_client, args=(clientsocket, addr))
        t.start()

if __name__ == "__main__":
    start_server()