import socket
import base64

from encryption import (
    generate_rsa_keys,
    generate_session_key,
    encrypt_session_key,
    aes_encrypt,
    aes_decrypt
)

from crypto_util import (
    caesar_encrypt,
    caesar_decrypt
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8888


# SOCKET FUNCTIONS
def send_packet(sock, packet):
    sock.sendall(packet.encode("utf-8"))


def receive_packet(sock):
    data = b""

    while True:
        chunk = sock.recv(4096)

        if not chunk:
            break

        data += chunk

        if len(chunk) < 4096:
            break

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

    secure_choice = input(
        "Use secure communication? (y/n): "
    ).strip().lower()

    # UNSECURED CONNECTION
    if secure_choice == "n":
        send_packet(sock, "(SS,RFMP,v1.0,0)")

        response = receive_packet(sock)
        print("\nServer:", response)

        if response == "(CC)":
            print("Unsecured connection setup complete.")

            return {
                "secure": False,
                "algorithm": None,
                "session_key": None
            }

        print("Setup failed.")
        return None

    # SECURED CONNECTION
    if secure_choice == "y":

        algorithm = input(
            "Choose encryption algorithm (AES/Caesar): "
        ).strip().upper()

        if algorithm not in ["AES", "CAESAR"]:
            print("Invalid encryption algorithm.")
            return None

        # Step 1: Tell server that secure communication is requested
        send_packet(sock, "(SS,RFMP,v1.0,1)")

        # Step 2: Receive server's public RSA key
        response = receive_packet(sock)
        print("\nServer:", response)

        if not response.startswith("(CC,") or not response.endswith(")"):
            print("Invalid secure setup response from server.")
            return None

        server_public_key_b64 = response[4:-1]

        try:
            server_public_key = base64.b64decode(
                server_public_key_b64
            )
        except Exception:
            print("Invalid server public key received.")
            return None

        print("Server public key received.")

        # Step 3: Generate client's RSA key pair
        client_public_key, client_private_key = generate_rsa_keys()

        # Step 4: Generate session key
        session_key = generate_session_key()

        # Step 5: Encrypt session key using server's RSA public key
        encrypted_session_key = encrypt_session_key(
            server_public_key,
            session_key
        )

        # Step 6: Base64 encode binary values for RFMP packet
        encrypted_session_key_b64 = base64.b64encode(
            encrypted_session_key
        ).decode("utf-8")

        client_public_key_b64 = base64.b64encode(
            client_public_key
        ).decode("utf-8")

        # Step 7: Ask for username
        username = input("Username: ").strip()

        # Step 8: Send EC packet
        ec_packet = (
            "(EC,"
            + algorithm
            + ","
            + encrypted_session_key_b64
            + ","
            + username
            + ":"
            + client_public_key_b64
            + ")"
        )

        send_packet(sock, ec_packet)

        # Step 9: Wait for server confirmation
        response = receive_packet(sock)
        print("\nServer:", response)

        if response.startswith("(SC"):
            print("Secure connection setup complete.")

            return {
                "secure": True,
                "algorithm": algorithm,
                "session_key": session_key,
                "client_private_key": client_private_key
            }

        print("Secure connection setup failed.")
        return None

    print("Invalid choice. Please enter y or n.")
    return None


# NORMAL COMMANDS
def send_command(sock, command):
    packet = f"(CM,prompt,{command})"

    send_packet(sock, packet)

    response = receive_packet(sock)

    handle_response(response)
# OPEN READ
def open_read(sock, secure):
    filename = input("Enter filename to read: ")

    if filename.strip() == "":
        print("Filename cannot be empty.")
        return

    packet = f"(CM,openRead,{filename})"
    send_packet(sock, packet)

    response = receive_packet(sock)

    if response.startswith("(EE"):
        print("\n[ERROR]")
        print(response)
        return

    # Make sure the DP packet wrapper is removed first.
    if response.startswith("(DP,") and response.endswith(")"):
        file_content = response[4:-1]
    else:
        file_content = response

    # Decrypt the file contents using AES.
    if secure and secure["algorithm"] == "AES":
        try:
            file_content = aes_decrypt(
                file_content,
                secure["session_key"]
            )
        except Exception as e:
            print("\n[ERROR]")
            print("Could not decrypt file contents:", e)
            return

    # Decrypt the file contents using Caesar.
    elif secure and secure["algorithm"] == "CAESAR":
        try:
            file_content = caesar_decrypt(file_content)
        except Exception as e:
            print("\n[ERROR]")
            print("Could not decrypt Caesar file contents:", e)
            return

    print("\n===== FILE CONTENT =====")
    print(file_content)
    print("=========================")
# OPEN WRITE
def open_write(sock, secure):
    filename = input("Enter filename to create/write: ")

    if filename.strip() == "":
        print("Filename cannot be empty.")
        return

    packet = f"(CM,openWrite,{filename}"
    send_packet(sock, packet)

    response = receive_packet(sock)

    handle_response(response)

    if response.startswith("(SC"):
        text = input("Enter text to write: ")

        # Encrypt text using AES before sending it to the server.
        if secure and secure["algorithm"] == "AES":
            text = aes_encrypt(
                text,
                secure["session_key"]
            )

        # Encrypt text using Caesar before sending it to the server.
        elif secure and secure["algorithm"] == "CAESAR":
            text = caesar_encrypt(text)

        data_packet = f"(DP,{text})"

        send_packet(sock, data_packet)

        response = receive_packet(sock)

        handle_response(response)


# MENU
def show_menu():
    print("\n")
    print("========== RFMP CLIENT ==========")

    # Required RFMP commands
    print("1. mkdir")
    print("2. cd")
    print("3. rmdir")
    print("4. del")
    print("5. ren")

    # Additional Windows system commands
    print("6. dir")
    print("7. whoami")
    print("8. hostname")
    print("9. date")
    print("10. systeminfo")

    # File operations
    print("11. openRead")
    print("12. openWrite")

    # Custom command
    print("13. Custom system command")

    # Exit
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

            # dir
            elif choice == "6":
                send_command(
                    client_socket,
                    "dir"
                )

            # whoami
            elif choice == "7":
                send_command(
                    client_socket,
                    "whoami"
                )

            # hostname
            elif choice == "8":
                send_command(
                    client_socket,
                    "hostname"
                )

            # date
            elif choice == "9":
                send_command(
                    client_socket,
                    "date"
                )

            # systeminfo
            elif choice == "10":
                send_command(
                    client_socket,
                    "systeminfo"
                )

            # openRead
            elif choice == "11":
                open_read(
                    client_socket,
                    secure
                )

            # openWrite
            elif choice == "12":
                open_write(
                    client_socket,
                    secure
                )

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
