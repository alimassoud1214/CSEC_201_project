#include <studio.h>
#include <string.h>
#include <winsock2.h>

int main() {
    WSADATA wsa;
    SOCKET sock;
    struct sockaddr_in server;
    char packet[200];
    char reply[5000];
    int n;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Winslock failed to start\n");
        return 1;
    }

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("Could not create socket\n");
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    server.sin_addr.s_addr = inet_addr("127.0.0.1);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("Connection failed\n");
        printf("make sure the server is running on port 8080\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    printf("Connected to RFMP server\n");

    strcpy(packet, "(SS,RFMP, v1.0,0)");
    send(sock, packet, strlen(packet), 0);

    n = recv(sock, reply, sizeof(reply) -1, 0);
    if (n <= 0) {
    printf("server connection closed\n");
    closesocket(sock);
    WSACleanup();
    return 1;
    }
    reply[n] = '\0';
    printf("Server reply: %s\n", reply);

    if(strcmp(reply, "(CC)") != 0) {
        printf("Server reply is not valid\n");
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    printf("unsecured connection established\n");

    closesocket(sock);
    WSACleanup();
    printf("Connection closed\n");
    return 0; 
}

