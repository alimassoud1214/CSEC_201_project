import socket
import threading
import os
import subprocess
import base64

from encryption import generate_rsa_keys, decrypt_session_key

# Bind to 0.0.0.0 so clients on Windows, Mac, and local networks can connect
HOST = "0.0.0.0"
PORT = 8888

# Generate the server's RSA public/private key pair.
SERVER_PUBLIC_KEY, SERVER_PRIVATE_KEY = generate_rsa_keys()

# Standard Rubric Error Codes (EE,ErrorCode,Description)
ERR_FILE_NOT_FOUND = "1"
ERR_MISSING_ARG = "2"
ERR_UNKNOWN_CMD = "3"
ERR_OP_FAILED = "4"

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

                public_key_b64 = base64.b64encode(
                    SERVER_PUBLIC_KEY
                ).decode("utf-8")

                cc_packet = "(CC," + public_key_b64 + ")"
                clientsocket.send(cc_packet.encode("utf-8"))

                print("Server RSA public key sent.")

                clientsocket.settimeout(5.0)

                try:
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
                                    f"(EE,{ERR_OP_FAILED},Unsupported encryption algorithm)".encode("utf-8")
                                )
                                return

                            encrypted_session_key = base64.b64decode(
                                encrypted_key_b64
                            )

                            session_key = decrypt_session_key(
                                SERVER_PRIVATE_KEY,
                                encrypted_session_key
                            )

                            print("Secure setup complete.")
                            print("Algorithm:", algorithm)

                            clientsocket.send(
                                "(SC,Secure communication established)".encode("utf-8")
                            )

                        else:
                            clientsocket.send(
                                f"(EE,{ERR_MISSING_ARG},Invalid EC packet)".encode("utf-8")
                            )
                            return

                    else:
                        clientsocket.send(
                            f"(EE,{ERR_UNKNOWN_CMD},Expected EC packet)".encode("utf-8")
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

            # Built-in directory commands
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
                            f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Missing directory name)".encode("utf-8")
                    )

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
                            f"(EE,{ERR_FILE_NOT_FOUND},Directory does not exist)".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Missing target directory)".encode("utf-8")
                    )

            elif cmd in ["rmdir", "rd"]:
                if len(tokens) > 1:
                    folder = tokens[1]

                    try:
                        os.rmdir(
                            os.path.join(current_dir, folder)
                        )

                        clientsocket.send(
                            f"(SC,Directory '{folder}' removed)".encode("utf-8")
                        )

                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Missing directory name)".encode("utf-8")
                    )

            elif cmd == "del":
                if len(tokens) > 1:
                    filename = tokens[1]

                    try:
                        os.remove(
                            os.path.join(current_dir, filename)
                        )

                        clientsocket.send(
                            f"(SC,File '{filename}' deleted)".encode("utf-8")
                        )

                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Missing filename)".encode("utf-8")
                    )

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
                            f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Usage: ren <old_name> <new_name>)".encode("utf-8")
                    )

            elif cmd in ["ls", "dir"]:
                try:
                    files = os.listdir(current_dir)

                    file_list = (
                        ", ".join(files)
                        if files
                        else "Directory empty"
                    )

                    clientsocket.send(
                        f"(SC,Files: {file_list})".encode("utf-8")
                    )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                    )

            elif cmd == "pwd":
                clientsocket.send(
                    f"(SC,{current_dir})".encode("utf-8")
                )

            # System commands
            elif cmd == "whoami":
                try:
                    result = subprocess.run(
                        "whoami",
                        shell=True,
                        cwd=current_dir,
                        capture_output=True,
                        text=True
                    )

                    output = result.stdout.strip()

                    clientsocket.send(
                        f"(SC,{output})".encode("utf-8")
                    )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                    )

            elif cmd == "hostname":
                try:
                    result = subprocess.run(
                        "hostname",
                        shell=True,
                        cwd=current_dir,
                        capture_output=True,
                        text=True
                    )

                    output = result.stdout.strip()

                    clientsocket.send(
                        f"(SC,{output})".encode("utf-8")
                    )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                    )

            elif cmd == "date":
                try:
                    # Windows uses cmd /c date /t, Mac/Linux uses date command
                    cmd_str = (
                        "cmd /c date /t"
                        if os.name == "nt"
                        else "date"
                    )

                    result = subprocess.run(
                        cmd_str,
                        shell=True,
                        cwd=current_dir,
                        capture_output=True,
                        text=True,
                        stdin=subprocess.DEVNULL
                    )

                    output = result.stdout.strip()

                    clientsocket.send(
                        f"(SC,{output})".encode("utf-8")
                    )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                    )

            elif cmd == "systeminfo":
                try:
                    # Windows uses systeminfo, Mac/Linux uses uname -a
                    cmd_str = (
                        "systeminfo"
                        if os.name == "nt"
                        else "uname -a"
                    )

                    result = subprocess.run(
                        cmd_str,
                        shell=True,
                        cwd=current_dir,
                        capture_output=True,
                        text=True,
                        stdin=subprocess.DEVNULL
                    )

                    output = result.stdout.strip()

                    clientsocket.send(
                        f"(SC,{output})".encode("utf-8")
                    )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                    )

            # File I/O operations
            elif cmd == "openread":
                if len(tokens) > 1:
                    filename = tokens[1]

                    file_path = os.path.join(
                        current_dir,
                        filename
                    )

                    if os.path.exists(file_path):
                        try:
                            file = open(file_path, "r")
                            content = file.read()
                            file.close()

                            clientsocket.send(
                                f"(DP,{content})".encode("utf-8")
                            )

                        except Exception as e:
                            clientsocket.send(
                                f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                            )

                    else:
                        clientsocket.send(
                            f"(EE,{ERR_FILE_NOT_FOUND},File not found)".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Missing filename)".encode("utf-8")
                    )

            elif cmd == "openwrite":
                if len(tokens) > 1:
                    filename = tokens[1]

                    file_path = os.path.join(
                        current_dir,
                        filename
                    )

                    clientsocket.send(
                        f"(SC,Ready to receive write data for {filename})".encode("utf-8")
                    )

                    dp_packet = clientsocket.recv(
                        16384
                    ).decode("utf-8")

                    text_data = dp_packet

                    if dp_packet.startswith("(DP,"):
                        text_data = dp_packet[4:-1]

                    try:
                        file = open(
                            file_path,
                            "a"
                        )

                        file.write(
                            text_data + "\n"
                        )

                        file.close()

                        clientsocket.send(
                            f"(SC,Successfully written to {filename})".encode("utf-8")
                        )

                    except Exception as e:
                        clientsocket.send(
                            f"(EE,{ERR_OP_FAILED},{str(e)})".encode("utf-8")
                        )

                else:
                    clientsocket.send(
                        f"(EE,{ERR_MISSING_ARG},Missing filename)".encode("utf-8")
                    )

            # System command fallback
            else:
                try:
                    result = subprocess.run(
                        msg,
                        cwd=current_dir,
                        shell=True,
                        capture_output=True,
                        text=True,
                        stdin=subprocess.DEVNULL
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
                        err_msg = (
                            error_output
                            if error_output
                            else f"Command failed with exit code {result.returncode}"
                        )

                        clientsocket.send(
                            f"(EE,{ERR_UNKNOWN_CMD},{err_msg})".encode("utf-8")
                        )

                except Exception as e:
                    clientsocket.send(
                        f"(EE,{ERR_UNKNOWN_CMD},{str(e)})".encode("utf-8")
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

    serversocket.bind(
        (HOST, PORT)
    )

    serversocket.listen(5)

    print(
        "Server is listening on port",
        PORT
    )

    while True:
        clientsocket, addr = serversocket.accept()

        thread = threading.Thread(
            target=handle_client,
            args=(clientsocket, addr)
        )

        thread.start()
if __name__ == "__main__":
    start_server()
