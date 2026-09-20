import socket

# SERVER SETTINGS
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888

# SOCKET FUNCTIONS
def send_packet(sock, packet):
    sock.sendall(packet.encode("utf-8"))


def receive_packet(sock):
    data = sock.recv(4096)

    if not data:
        return ""

    return data.decode("utf-8")

# RESPONSE HANDLING
def handle_response(response):
    if response.startswith("(SC"):
        print("\n[SUCCESS]")
        print(response)

    elif response.startswith("(EE"):
        print("\n[ERROR]")
        print(response)

    else:
        print("\n[SERVER]")
        print(response)

# SETUP PHASE
def setup_connection(sock):

    print("\n===== RFMP SETUP =====")

    security = input(
        "Use secure communication? (y/n): "
    ).lower()

    if security == "y":
        start_packet = "(SS,RFMP,v1.0,1)"
    else:
        start_packet = "(SS,RFMP,v1.0,0)"
    # Send Start Packet
    send_packet(sock, start_packet)

    # Receive Confirm Connection Packet
    response = receive_packet(sock)

    print("\nServer:", response)
    # Non-secure connection
    if security != "y":

        if response == "(CC)":
            print("Unsecured connection setup complete.")
            return False

        print("Unexpected server response.")
        return False
    
    # Secure connection
    if response.startswith("(CC,"):
        print("Server public key received.")
        # Extract server public key
        server_public_key = response[4:-1]

        print("Server public key:", server_public_key)

        # ENCRYPTION WILL BE ADDED HERE WITH PERSON 3
        # The server currently expects:
        # (EC,Algorithm,EncryptedSessionKey,ClientPublicKey)
        # Person 3's crypto_util.py will be integrated
        # here.
        print("Secure encryption setup still needs to be integrated.")

        return True

    print("Unexpected server response.")
    return False

# NORMAL COMMANDS
def send_command(sock, command):
    packet = f"(CM,prompt,{command})"

    send_packet(sock, packet)

    response = receive_packet(sock)

    handle_response(response)
# OPEN READ
def open_read(sock):

    filename = input("Enter filename to read: ")

    if filename.strip() == "":
        print("Filename cannot be empty.")
        return

    packet = f"(CM,openRead,{filename})"

    send_packet(sock, packet)

    response = receive_packet(sock)

    print("\n===== FILE CONTENT =====")
    print(response)
    print("=========================")
# OPEN WRITE
def open_write(sock):

    filename = input(
        "Enter filename to create/write: "
    )
    if filename.strip() == "":
        print("Filename cannot be empty.")
        return

    packet = f"(CM,openWrite,{filename})"

    send_packet(sock, packet)

    response = receive_packet(sock)

    handle_response(response)
    if response.startswith("(SC"):

        text = input("Enter text to write: ")

        data_packet = f"(DP,{text})"

        send_packet(sock, data_packet)

        response = receive_packet(sock)

        handle_response(response)

# MENU
def show_menu():

    print("\n")
    print("========== RFMP CLIENT ==========")
    print("1. mkdir")
    print("2. cd")
    print("3. rmdir")
    print("4. del")
    print("5. ren")
    print("6. ls")
    print("7. pwd")
    print("8. whoami")
    print("9. date")
    print("10. uname")
    print("11. openRead")
    print("12. openWrite")
    print("13. Custom system command")
    print("14. Exit")
    print("=================================")

# MAIN PROGRAM
def main():
    # Create TCP socket
    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    try:
        # Connect to server
        client_socket.connect(
            (SERVER_HOST, SERVER_PORT)
        )

        print("\nConnected to RFMP server.")

        # SETUP PHASE
        secure = setup_connection(client_socket)

        # OPERATION PHASE
        while True:

            show_menu()

            choice = input("Choose an option: ")
            # mkdir
            if choice == "1":

                folder = input("Folder name: ")

                send_command(
                    client_socket,
                    f"mkdir {folder}"
                )
            # cd
            elif choice == "2":

                path = input("Directory path: ")

                send_command(
                    client_socket,
                    f"cd {path}"
                )
            # rmdir
            elif choice == "3":

                folder = input("Folder name: ")

                send_command(
                    client_socket,
                    f"rmdir {folder}"
                )
            # del
            elif choice == "4":

                filename = input("File name: ")

                send_command(
                    client_socket,
                    f"del {filename}"
                )
            # ren
            elif choice == "5":

                old_name = input("Current name: ")
                new_name = input("New name: ")

                send_command(
                    client_socket,
                    f"ren {old_name} {new_name}"
                )
            # ls
            elif choice == "6":

                send_command(
                    client_socket,
                    "ls"
                )
            # pwd
            elif choice == "7":

                send_command(
                    client_socket,
                    "pwd"
                )
            # whoami
            elif choice == "8":

                send_command(
                    client_socket,
                    "whoami"
                )
            # date
            elif choice == "9":

                send_command(
                    client_socket,
                    "date"
                )
            # uname
            elif choice == "10":

                send_command(
                    client_socket,
                    "uname"
                )
            # openRead
            elif choice == "11":

                open_read(client_socket)
            # openWrite
            elif choice == "12":

                open_write(client_socket)
            # Custom command
            elif choice == "13":

                command = input(
                    "Enter system command: "
                )

                if command.strip() == "":
                    print("Command cannot be empty.")
                    continue
            
                send_command(
                    client_socket,
                    command
                )
            # Exit
            elif choice == "14":
                print("\nClosing connection...")

                send_packet(
                    client_socket,
                    "(End)"
                )
                response = receive_packet(
                    client_socket
                )
                if response:
                    print("Server:", response)

                break

            else:

                print("\nInvalid option.")

    except ConnectionRefusedError:

        print("\nCould not connect to the server.")
        print("Make sure the server is running on port 8888.")

    except ConnectionResetError:
        print("\nThe server closed the connection.")

    except Exception as e:
        print("\nAn error occurred:")
        print(e)

    finally:
        client_socket.close()

        print("Client closed.")
# START PROGRAM
if __name__ == "__main__":
    main()