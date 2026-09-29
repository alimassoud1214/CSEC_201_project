#include <stdio.h>      // printf() to print, scanf() to read user input
#include <string.h>     // strcpy, strcat, strcmp, strncmp, strlen (string functions)
#include <winsock2.h>   // Winsock 2: the Windows version of the socket library

int main() {
    WSADATA wsa;                // Struct that WSAStartup() fills with info about
                                // the Winsock version that was loaded.

    SOCKET sock;                // The socket = our "connection" to the server.
                                // On Windows the type is SOCKET (not int like Linux).

    struct sockaddr_in server;  // Struct that stores WHERE to connect:
                                // address family (IPv4), port number, IP address.

    char packet[200];           // Array of chars (a string) used to build every
                                // packet we SEND to the server.

    char reply[5000];           // Array of chars used to store every packet we
                                // RECEIVE from the server (5000 bytes is enough
                                // for small test files).

    char filename[100];         // The file name the user types (e.g. test.txt).

    int n;                      // Stores the return value of recv():
                                //   n > 0  -> number of bytes received
                                //   n == 0 -> server closed the connection
                                //   n < 0  -> an error happened

    // Starting Winsock.
    // On Windows, the socket library must be started before ANY socket
    // function is used. MAKEWORD(2, 2) asks for Winsock version 2.2.
    // &wsa passes the ADDRESS of wsa (a pointer) so the function can fill it.
    // It returns 0 on success, anything else means it failed.
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Winsock failed to start\n");
        return 1;                 // return 1 = program ended with an error
    }

    // STEP 2: Create the socket.
    //   AF_INET     -> use IPv4 addresses
    //   SOCK_STREAM -> use TCP
    //   0           -> let the system pick the protocol
    sock = socket(AF_INET, SOCK_STREAM, 0);

    // If the socket could not be created, Windows returns INVALID_SOCKET.
    // We must call WSACleanup() before exiting to shut Winsock down properly.
    if (sock == INVALID_SOCKET) {
        printf("Could not create socket\n");
        WSACleanup();
        return 1;
    }

    // STEP 3: Fill in the server's address.
    server.sin_family = AF_INET;          // IPv4, must match the socket above

    server.sin_port = htons(8888);        // Port 8888 = same port the Python server listens on.
                                          // htons = "host to network short": converts the
                                          // number to network byte order.

    server.sin_addr.s_addr = inet_addr("127.0.0.1");
                                          // 127.0.0.1 = localhost = this same computer.
                                          // inet_addr converts the IP from text.
                                          // into the 4-byte number the socket needs.

    // STEP 4: Connect to the server
    // (struct sockaddr *)&server connect() expects a generic sockaddr
    // pointer, so we cast our sockaddr_in to it.
    // sizeof(server) tells connect() how big the address struct is.
    // connect() returns a negative value if it fails (e.g. server not running).
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection failed\n");
        printf("make sure the server is running on port 8888\n");
        closesocket(sock);        // close the socket we created
        WSACleanup();             // shut down Winsock
        return 1;
    }

    printf("Connected to RFMP server\n");

    // STEP 5: Send the Start Packet.
    // Format from the assignment: (packet-type, protocol, version, secured)
    //   SS   -> packet type "Start"
    //   RFMP -> protocol name
    //   v1.0 -> protocol version
    //   0    -> NO secured communication (the C client never uses encryption,
    //           so the server will NOT expect an Encryption Packet (EC))
    // strcpy copies the text into our packet array.
    strcpy(packet, "(SS,RFMP,v1.0,0)");

    // send(socket, data, length, flags)
    // strlen(packet) = number of characters to send (without the '\0').
    // flags = 0 means normal sending, no special options.
    send(sock, packet, strlen(packet), 0);

    // STEP 6: Receive the Confirm Connection packet (CC).
    // recv(socket, buffer, max bytes, flags) waits until data arrives.
    // We use sizeof(reply) - 1 so there is always 1 free byte left
    // at the end to put the '\0' (string terminator).
    n = recv(sock, reply, sizeof(reply) - 1, 0);

    // If n is 0 the server closed the connection, if negative there was an
    // error. Either way we cannot continue, so we clean up and exit.
    if (n <= 0) {
        printf("server connection closed\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    // recv() gives us raw bytes, it does NOT add '\0' at the end.
    // In C a string must end with '\0', otherwise printf would keep reading
    // garbage memory after our data. So we add it ourselves at position n.
    reply[n] = '\0';
    printf("Server reply: %s\n", reply);

    // STEP 7: Check the reply.
    // In non-secured mode the assignment says the server sends ONE field: (CC).
    // (In secured mode it would be (CC,Server_public_key), but we don't use that.)
    // strcmp returns 0 when two strings are exactly equal.
    if (strcmp(reply, "(CC)") != 0) {
        printf("Server reply is not valid\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("unsecured connection established\n");



    // STEP 8: Ask the user for a file name.
    // %s reads one word (stops at a space).
    // No & is needed because filename is an array, and the array name
    // is already the address of its first cell.
    printf("\nEnter filename to read: ");
    scanf("%s", filename);

    // STEP 9: Build the command packet: (CM,openRead,filename)
    //   CM =packet type "Command"
    //   openRead tells the server to open the file in READ mode
    //   filename = the file to read
    // strcpy puts the first part in the array, then strcat ADDS
    // (concatenates) each next part to the end of the string.
    // Example: "(CM,openRead," + "test.txt" + ")" = "(CM,openRead,test.txt)"
    strcpy(packet, "(CM,openRead,");
    strcat(packet, filename);
    strcat(packet, ")");
    send(sock, packet, strlen(packet), 0);

    // STEP 10: Receive the server's answer.
    // It is either the file contents, or an Exception Packet (EE) if
    // something went wrong (e.g. the file does not exist).
    n = recv(sock, reply, sizeof(reply) - 1, 0);
    if (n > 0) {                  // only print if we actually received data
        reply[n] = '\0';          // end the string (same reason as step 6)

        // Exception Packet format from the assignment: (EE,ErrorCode,Description)
        // strncmp compares only the first 3 characters, so any reply that
        // STARTS with "(EE" is treated as an error, whatever the code is.
        if (strncmp(reply, "(EE", 3) == 0) {
            printf("\n[ERROR]\n%s\n", reply);
        } else {
            // Not an error -> show the file contents
            printf("\n===== FILE CONTENT =====\n");
            printf("%s\n", reply);
            printf("========================\n");
        }
    }


    // STEP 11: Send the End packet.
    // The assignment says (End) tells the server the client is finished,
    // and the server should expect no more messages from this client.
    printf("\nClosing connection...\n");
    strcpy(packet, "(End)");
    send(sock, packet, strlen(packet), 0);

    // STEP 12: Receive the server's final reply, if it sends one.
    // If the server just closes the connection, n will be 0 and we skip printing.
    n = recv(sock, reply, sizeof(reply) - 1, 0);
    if (n > 0) {
        reply[n] = '\0';
        printf("Server: %s\n", reply);
    }

    // STEP 13: Clean up.
    // closesocket() closes our connection (Windows version of close()).
    // WSACleanup() shuts down Winsock (must match the WSAStartup() call).
    closesocket(sock);
    WSACleanup();
    printf("Connection closed\n");
    return 0;                     // return 0 = program ended successfully
}