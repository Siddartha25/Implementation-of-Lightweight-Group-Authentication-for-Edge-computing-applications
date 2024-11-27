#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <vector>
#include <bits/stdc++.h>
#include <thread>

#define PORT 8080
#define PORT2 80802
#define PORT1 80801
#define MAX_CLIENTS 4
#define BUFFER_SIZE 10024
using namespace std;

void receiveoneMessage(int socket) {
    char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        int bytesRead = read(socket, buffer, BUFFER_SIZE);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::cout << "Received: " << buffer << std::endl;
        }
}
void broadcastToGL(int senderSocket, const std::vector<int>& clients, const char* message) {
    for (int clientSocket : clients) {
        if (clientSocket != senderSocket) {  // Don't send to the sender itself
            send(clientSocket, message, strlen(message), 0);
        }
    }
}

int server() {

        /*connecting to S3*/
            int clientSocket1;
            char buffer[BUFFER_SIZE];
            struct sockaddr_in serverAddr1;

            // Create socket
            clientSocket1 = socket(AF_INET, SOCK_STREAM, 0);
            if (clientSocket1 < 0) {
                std::cerr << "Socket creation error\n";
                exit(EXIT_FAILURE);
            }

            serverAddr1.sin_family = AF_INET;
            serverAddr1.sin_port = htons(PORT1);
            serverAddr1.sin_addr.s_addr = inet_addr("127.0.0.1");  // Assuming local server

            // Connect to server
            if (connect(clientSocket1, (struct sockaddr*)&serverAddr1, sizeof(serverAddr1)) < 0) {
                std::cerr << "Connection failed\n";
                exit(EXIT_FAILURE);
            }

            std::cout << "Connected to S3\n";

/*it will store the broadcast message that it receives from S3 ie AS*/

            memset(buffer, 0, BUFFER_SIZE);
            int bytesRead = read(clientSocket1, buffer, BUFFER_SIZE);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::cout << "Received: " << buffer << std::endl;
            }

/*it will allow certain number of GL to be connected to it*/
    int serverSocket, clientSocket, activity;
    struct sockaddr_in serverAddr, clientAddr;
    fd_set readfds;
    std::vector<int> clients;

    // Create server socket
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == 0) {
        std::cerr << "Socket creation error\n";
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT2);

    // Bind the socket
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Bind failed\n";
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(serverSocket, 5) < 0) {
        std::cerr << "Listen failed\n";
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port " << PORT2 << std::endl;
    socklen_t addrLen = sizeof(clientAddr);

    int maxGl=1;
    while (true) {
        FD_ZERO(&readfds);
        FD_SET(serverSocket, &readfds);
        FD_SET(STDIN_FILENO, &readfds);  // Add stdin to the set for server input
        int maxFd = serverSocket;

        // Add all client sockets to the readfds set
        for (int clientSocket : clients) {
            FD_SET(clientSocket, &readfds);
            if (clientSocket > maxFd)
                maxFd = clientSocket;
        }

        // Wait for activity
        activity = select(maxFd + 1, &readfds, nullptr, nullptr, nullptr);
        if (activity < 0) {
            std::cerr << "Select error\n";
            continue;
        }

        // Handle new connections
        if (FD_ISSET(serverSocket, &readfds)) {
            clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &addrLen);
            if (clientSocket < 0) {
                std::cerr << "Accept error\n";
                continue;
            }

            std::cout << "New connection from client\n";
            clients.push_back(clientSocket);
            if(clients.size()>=maxGl){break;}
        }
    }

/*it will broadcast the message it got from S3 to all the GL*/
    // const char* Message_to_S1 = buffer;
    // std::cout << "message to GL: " << Message_to_S1 << std::endl;
    broadcastToGL(-1, clients, buffer);


/*it will wait for each group leader to do internal processing within the group and after the GL sends it to S2 it will send it to S3*/
    for (size_t i = 0; i < clients.size(); ++i) {
            clientSocket = clients[i];
            memset(buffer, 0, BUFFER_SIZE);
            int bytesRead = read(clientSocket, buffer, BUFFER_SIZE);
            if (bytesRead > 0) {
                buffer[bytesRead] = '\0';
                std::cout << "Received tag info from GL : " << buffer << std::endl;
            }
            send(clientSocket1, buffer, strlen(buffer), 0);
    }

}

int main() {
    server();
    return 0;
}
