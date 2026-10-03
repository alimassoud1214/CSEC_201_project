import socket
import threading
import os
import subprocess
import base64
from encryption import generate_rsa_keys, decrypt_session_key
from crypto_util import caesar_encrypt, caesar_decrypt

HOST = "127.0.0.1"
PORT = 8888

# Generate the server's RSA public/private key pair.
SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = generate_rsa_keys()

def handle_client(clientsocket, addr):
    print("Got a connection from %s" % str(addr))

    current_dir = os.getcwd()
    session_key = b""
    algorithm = ""
    is_secured = False

    try:
        # Receive the client's setup packet.
        req = clientsocket.recv(2024).decode("utf-8")
        print("Received setup packet:", req)

        clean_ss = req.replace("(", "").replace(")", "").split(",")

        if clean_ss[0] == "SS" and clean_ss[1] == "RFMP":
            security_mode = clean_ss[3]

            if security_mode == "0":
                clientsocket.send("(CC)".encode("utf-8"))

            elif security_mode == "1":
                is_secured = True
                # Base64 makes the RSA public key safe to send inside the RFMP packet.
                public_key_b64 = base64.b64encode(
                    SERVER_PUBLIC_KEY
                ).decode("utf-8")

                cc_packet = "(CC," + public_key_b64 + ")"
                clientsocket.send(cc_packet.encode("utf-8"))

                print("Server RSA public key sent.")

                # Set a timeout for receiving the EC packet.
                clientsocket.settimeout(30.0)
                try:
                    # Receive the client's encryption details and encrypted session key.
                    ec_req = clientsocket.recv(16384).decode("utf-8")
                    print("Received encryption details:", ec_req)

                    if ec_req.startswith("(EC,"):
                        clean_ec = ec_req[4:-1].split(",", 2)

                        if len(clean_ec) >= 3:
                            algorithm = clean_ec[0]
                            encrypted_key_b64 = clean_ec[1]
                            client_information = clean_ec[2]

                            if algorithm.upper() not in ["AES", "CAESAR"]:
                                clientsocket.send(
                                    "(EE,Unsupported encryption algorithm)".encode("utf-8")
                                )
                                return

                            # Decode the Base64 RSA-encrypted session key.
                            encrypted_session_key = base64.b64decode(
                                encrypted_key_b64
                            )

                            # Decrypt the session key using the server's RSA private key.
                            session_key = decrypt_session_key(
                                SERVER_PRIVATE_KEY,
                                encrypted_session_key
                            )

                            print("Secure setup complete.")
                            print("Algorithm:", algorithm)
                            print("Client information received.")

                            clientsocket.send(
                                "(SC,Secure communication established)".encode("utf-8")
                            )
                        else:
                            clientsocket.send(
                                "(EE,Invalid EC packet)".encode("utf-8")
                            )
                            return
                    else:
                        clientsocket.send(
                            "(EE,Expected EC packet)".encode("utf-8")
                        )
                        return

                except socket.timeout:
                    print("No EC packet received from client.")
                    return

                finally:
                    clientsocket.settimeout(None)
        while True:
            cmd_data = clientsocket.recv(16384).decode("utf-8")

            if not cmd_data:
                break

            msg = cmd_data.strip()
            print("Received command:", msg)
            # Remove the RFMP command packet wrapper.
            if msg.startswith("(CM,"):
                msg = msg[4:-1]
                parts = msg.split(",", 1)

                if len(parts) == 2:
                    command_type = parts[0]
                    arguments = parts[1]
                    print("DEBUG filename/arguments received:", repr(arguments)) 
                    if command_type.lower() in ["openread", "openwrite"]:
                        msg = command_type + " " + arguments
                    else:
                        msg = arguments

            # Close the client session.
            if msg in ["(End)", "exit", "close", "quit"]:
                clientsocket.send(
                    "(SC,Session Closed)".encode("utf-8")
                )
                print("Client disconnected.")
                break

            tokens = msg.split()

            if not tokens:
                continue

            cmd = tokens[0].lower()
            # Create a directory.
            if cmd == "mkdir":
                if len(tokens) > 1:
                    folder = tokens[1]
                    try:
                        os.mkdir(os.path.join(current_dir, folder))
                        clientsocket.send(
                            f"(SC,Directory '{folder}' created)".encode("utf-8")
                        )
                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{str(e)})".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Missing directory name)".encode("utf-8")
                    )
            # Change the current server directory.
            elif cmd == "cd":
                if len(tokens) > 1:
                    target = tokens[1]
                    new_path = os.path.abspath(
                        os.path.join(current_dir, target)
                    )

                    if os.path.exists(new_path) and os.path.isdir(new_path):
                        current_dir = new_path
                        clientsocket.send(
                            f"(SC,Changed directory to {current_dir})".encode("utf-8")
                        )
                    else:
                        clientsocket.send(
                            "(EE,Directory does not exist)".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Missing target directory)".encode("utf-8")
                    )

            # Remove an empty directory.
            elif cmd == "rmdir" or cmd == "rd":
                if len(tokens) > 1:
                    folder = tokens[1]
                    try:
                        os.rmdir(os.path.join(current_dir, folder))
                        clientsocket.send(
                            f"(SC,Directory '{folder}' removed)".encode("utf-8")
                        )
                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{str(e)})".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Missing directory name)".encode("utf-8")
                    )
            # Delete a file.
            elif cmd == "del":
                if len(tokens) > 1:
                    filename = tokens[1]
                    try:
                        os.remove(os.path.join(current_dir, filename))
                        clientsocket.send(
                            f"(SC,File '{filename}' deleted)".encode("utf-8")
                        )
                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{str(e)})".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Missing filename)".encode("utf-8")
                    )
            # Rename a file or directory.
            elif cmd == "ren":
                if len(tokens) > 2:
                    old_name = tokens[1]
                    new_name = tokens[2]
                    try:
                        os.rename(
                            os.path.join(current_dir, old_name),
                            os.path.join(current_dir, new_name)
                        )
                        clientsocket.send(
                            f"(SC,Renamed '{old_name}' to '{new_name}')".encode("utf-8")
                        )
                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{str(e)})".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Usage: ren <old_name> <new_name>)".encode("utf-8")
                    )

            # List files in the current directory.
            elif cmd == "ls" or cmd == "dir":
                try:
                    files = os.listdir(current_dir)
                    file_list = ", ".join(files) if files else "Directory empty"

                    clientsocket.send(
                        f"(SC,Files: {file_list})".encode("utf-8")
                    )
                except Exception as e:
                    clientsocket.send(
                        f"(EE,{str(e)})".encode("utf-8")
                    )

            # Return the current server directory.
            elif cmd == "pwd":
                clientsocket.send(
                    f"(SC,{current_dir})".encode("utf-8")
                )
            # Return the Windows username running the server.
            elif cmd == "whoami":
                try:
                    result = subprocess.run(
                        ["whoami"],
                        cwd=current_dir,
                        capture_output=True,
                        text=True
                    )
                    output = result.stdout.strip()
                    if result.returncode == 0:
                        clientsocket.send(
                            f"(SC,{output})".encode("utf-8")
                        )
                    else:
                        clientsocket.send(
                            f"(EE,{result.stderr.strip()})".encode("utf-8")
                        )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{str(e)})".encode("utf-8")
                    )
            # Return the server computer's hostname.
            elif cmd == "hostname":
                try:
                    result = subprocess.run(
                        ["hostname"],
                        cwd=current_dir,
                        capture_output=True,
                        text=True
                    )

                    output = result.stdout.strip()

                    if result.returncode == 0:
                        clientsocket.send(
                            f"(SC,{output})".encode("utf-8")
                        )
                    else:
                        clientsocket.send(
                            f"(EE,{result.stderr.strip()})".encode("utf-8")
                        )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{str(e)})".encode("utf-8")
                    )
            # Windows does not use the same "date" command behavior as Linux,
            # so cmd.exe is used to display the current date.
            elif cmd == "date":
                try:
                    result = subprocess.run(
                        ["cmd", "/c", "date", "/t"],
                        cwd=current_dir,
                        capture_output=True,
                        text=True
                    )

                    output = result.stdout.strip()

                    if result.returncode == 0:
                        clientsocket.send(
                            f"(SC,{output})".encode("utf-8")
                        )
                    else:
                        clientsocket.send(
                            f"(EE,{result.stderr.strip()})".encode("utf-8")
                        )
                except Exception as e:
                    clientsocket.send(
                        f"(EE,{str(e)})".encode("utf-8")
                    )
            # Display Windows system information.
            elif cmd == "systeminfo":
                try:
                    result = subprocess.run(
                        ["systeminfo"],
                        cwd=current_dir,
                        capture_output=True,
                        text=True
                    )

                    output = result.stdout.strip()

                    if result.returncode == 0:
                        clientsocket.send(
                            f"(SC,{output})".encode("utf-8")
                        )
                    else:
                        clientsocket.send(
                            f"(EE,{result.stderr.strip()})".encode("utf-8")
                        )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{str(e)})".encode("utf-8")
                    )
            # Read the contents of a file.
            elif cmd == "openread":
                if len(tokens) > 1:
                    filename = tokens[1]
                    file_path = os.path.join(current_dir, filename)

                    if os.path.exists(file_path):
                        try:
                            file = open(file_path, "r")
                            content = file.read()
                            file.close()

                            # Encrypt file contents when secure AES communication is active.
                            if is_secured and algorithm.upper() == "AES":
                                from encryption import aes_encrypt
                                content = aes_encrypt(
                                    content,
                                    session_key
                                )

                            # Encrypt file contents when secure Caesar communication is active.
                            elif is_secured and algorithm.upper() == "CAESAR":
                                content = caesar_encrypt(content)

                            clientsocket.send(
                                f"(DP,{content})".encode("utf-8")
                            )

                        except Exception as e:
                            clientsocket.send(
                                f"(EE,{str(e)})".encode("utf-8")
                            )
                    else:
                        clientsocket.send(
                            "(EE,File not found)".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Missing filename)".encode("utf-8")
                    )
            # Write data received from the client into a file.
            elif cmd == "openwrite":
                if len(tokens) > 1:
                    filename = tokens[1]
                    file_path = os.path.join(current_dir, filename)

                    clientsocket.send(
                        f"(SC,Ready to receive write data for {filename})".encode("utf-8")
                    )

                    dp_packet = clientsocket.recv(16384).decode("utf-8")
                    text_data = dp_packet

                    if dp_packet.startswith("(DP,") and dp_packet.endswith(")"):
                        text_data = dp_packet[4:-1]

                    try:
                        # Decrypt the incoming data when secure AES communication is active.
                        if is_secured and algorithm.upper() == "AES":
                            from encryption import aes_decrypt

                            text_data = aes_decrypt(
                                text_data,
                                session_key
                            )

                        # Decrypt the incoming data when secure Caesar communication is active.
                        elif is_secured and algorithm.upper() == "CAESAR":
                            text_data = caesar_decrypt(text_data)

                        file = open(file_path, "a")
                        file.write(text_data + "\n")
                        file.close()

                        clientsocket.send(
                            f"(SC,Successfully written to {filename})".encode("utf-8")
                        )

                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{str(e)})".encode("utf-8")
                        )
                else:
                    clientsocket.send(
                        "(EE,Missing filename)".encode("utf-8")
                    )
            # Any command not handled above is executed as a Windows system command.
            else:
                try:
                    result = subprocess.run(
                        msg,
                        cwd=current_dir,
                        shell=True,
                        capture_output=True,
                        text=True
                    )

                    output = result.stdout.strip()
                    error_output = result.stderr.strip()

                    if result.returncode == 0:
                        if output:
                            clientsocket.send(
                                f"(SC,{output})".encode("utf-8")
                            )
                        else:
                            clientsocket.send(
                                "(SC,Command executed successfully)".encode("utf-8")
                            )
                    else:
                        if error_output:
                            clientsocket.send(
                                f"(EE,{error_output})".encode("utf-8")
                            )
                        else:
                            clientsocket.send(
                                f"(EE,Command failed with exit code {result.returncode})".encode("utf-8")
                            )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{str(e)})".encode("utf-8")
                    )
    except Exception as e:
        print("Error handling client:", e)

    finally:
        clientsocket.close()
def start_server():
    serversocket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    serversocket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )
    serversocket.bind((HOST, PORT))
    serversocket.listen(5)

    print("Server is listening on port", PORT)

    while True:
        clientsocket, addr = serversocket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(clientsocket, addr)
        )
        thread.start()
if __name__ == "__main__":
    start_server()
