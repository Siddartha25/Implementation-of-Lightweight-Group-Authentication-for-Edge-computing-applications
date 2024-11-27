#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <vector>
#include <bits/stdc++.h>
#include <thread>
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <climits>

#define PORT 8080
#define PORT1 80801
#define PORT2 80802
#define MAX_CLIENTS 4
#define BUFFER_SIZE 10024
using namespace std;


std::string sha256(const std::string& input) {
    // Buffer to hold the hash output
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Compute SHA-256 hash
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.size());
    SHA256_Final(hash, &sha256);

    // Convert the hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

std::vector<int> generateRandomNumbers(int N, int t) {
    std::vector<int> numbers;
    for (int i = 1; i <= N; ++i) {
        numbers.push_back(i);
    }
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    std::shuffle(numbers.begin(), numbers.end(), std::default_random_engine(seed));
    std::vector<int> random_numbers(numbers.begin(), numbers.begin() + t);
    return random_numbers;
}

std::string getCurrentTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* local_time = std::localtime(&now_c);
    char buffer[15]; // 14 characters + 1 for null terminator
    std::strftime(buffer, sizeof(buffer), "%d%m%Y%H%M", local_time);
    return std::string(buffer); // Return as string
}

string nodes_selected(int N,int t){
    string s1="";
    vector<int> temp=generateRandomNumbers(N,t);
    for(int i=0;i<temp.size();i++){
        s1+=to_string(temp[i]);
        if(i!=temp.size()-1){
            s1+="-";
        }
    }
    string time=getCurrentTime();
    string s=s1+"/"+time+"/"+sha256(s1+time);
    return s;
}

void receiveoneMessage(int socket) {
    char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        int bytesRead = read(socket, buffer, BUFFER_SIZE);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::cout << "Received: " << buffer << std::endl;
        }
}
void broadcastToClients(int senderSocket, const std::vector<int>& clients, const char* message) {
    for (int clientSocket : clients) {
        if (clientSocket != senderSocket) {  // Don't send to the sender itself
            send(clientSocket, message, strlen(message), 0);
        }
    }
}

int count_nodes=0;
string messageto_edge="";

int server() {

    /*connecting to S2*/
    int clientSocket1;
    struct sockaddr_in serverAddr1;
    char buffer[BUFFER_SIZE];

    // Create socket
    clientSocket1 = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket1 < 0) {
        std::cerr << "Socket creation error\n";
        exit(EXIT_FAILURE);
    }

    serverAddr1.sin_family = AF_INET;
    serverAddr1.sin_port = htons(PORT2);
    serverAddr1.sin_addr.s_addr = inet_addr("127.0.0.1");  // Assuming local server

    // Connect to server
    if (connect(clientSocket1, (struct sockaddr*)&serverAddr1, sizeof(serverAddr1)) < 0) {
        std::cerr << "Connection failed\n";
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to S2\n";

/*the Gl receives the broadcast message from S2*/
    const char* temp;
    char buffer1[BUFFER_SIZE];
    memset(buffer1, 0, BUFFER_SIZE);
    int bytesRead = read(clientSocket1, buffer1, BUFFER_SIZE);
    temp=buffer1;
        if (bytesRead > 0) {
            buffer1[bytesRead] = '\0';
            std::cout << "Received: " << buffer1 << std::endl;
        }

/*Gl does the internal auth within its group*/

    /*now it acts as server ie GL to clients/nodes */

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
    serverAddr.sin_port = htons(PORT);

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

    std::cout << "Server listening on port " << PORT << std::endl;
    socklen_t addrLen = sizeof(clientAddr);

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
        }

        // Handle client messages
        for (size_t i = 0; i < clients.size(); ++i) {
            clientSocket = clients[i];
            if (FD_ISSET(clientSocket, &readfds)) {
                memset(buffer, 0, BUFFER_SIZE);
                int bytesRead = read(clientSocket, buffer, BUFFER_SIZE);
                if (bytesRead == 0) {  // Client disconnected
                    std::cout << "Client disconnected\n";
                    close(clientSocket);
                    clients.erase(clients.begin() + i);
                    --i;
                } else {
                    buffer[bytesRead] = '\0';
                    std::cout << "Message from client: " << buffer << std::endl;

                    // Check if the message starts with "broadcast" ie does the client want the message to be broadcasted within the group
                    if (strncmp(buffer, "broadcast ", 10) == 0) {
                        // Extract the actual message after "broadcast"
                        const char* broadcastMessage = buffer + 10;
                        std::cout << "Broadcasting message: " << broadcastMessage << std::endl;
                        // Send the message to all other clients
                        broadcastToClients(clientSocket, clients, broadcastMessage);
                    } 
                    else if(strncmp(buffer, "macid ", 6) == 0){
                        const char* tagid_to_S2 = buffer + 6;
                        string temp(tagid_to_S2);
                        messageto_edge+="/"+temp;
                        count_nodes++;
                        // std::cout << "message to edge layer: " << tagid_to_S2 << std::endl;
                        // send(clientSocket1, tagid_to_S2, strlen(tagid_to_S2), 0);
                    }
                    // else {
                    //     // Handle direct message to the server ie send confirmation message
                    //     send(clientSocket, "Message received by server", 26, 0);
                    // }
                }
            }
        }

        // Handle server input
        if (FD_ISSET(STDIN_FILENO, &readfds)) {
            memset(buffer, 0, BUFFER_SIZE);
            std::cin.getline(buffer, BUFFER_SIZE);  // Read input from the server console

            /*ie after all internal processing if we want to send to S2*/
            if (strncmp(buffer, "S2 ", 3) == 0) {
                        // Extract the actual message after "S2"
                        const char* Message_to_S2 = buffer + 3;
                        std::cout << "message to edge layer: " << Message_to_S2 << std::endl;
                        send(clientSocket1, Message_to_S2, strlen(Message_to_S2), 0);
            }
            /*if the server wanst to broadcast within its group*/
            else if(strncmp(buffer, "Send1 ", 6) == 0){
                // Server broadcasts the message it got from s2 to all cliemts
                std::cout << "Server broadcasting: " << temp << std::endl;
                broadcastToClients(-1, clients, temp);  // it will broadcast the messae it got from S2 to all clients
            }
            else if(strncmp(buffer, "Send2 ", 6) == 0){
                // Server broadcasts the clients it selected for sending their pair
                string s=nodes_selected(3,2); //ie from 3 clients choose 2 to braodcast the pairs 
                const char * temp=s.c_str();
                std::cout << "Server broadcasting: " << temp << std::endl;
                broadcastToClients(-1, clients, temp);  // it will broadcast the messae it got from S2 to all clients
            }
        }

        if(count_nodes==3){
            const char* Message_to_S2 = messageto_edge.c_str();
            std::cout << "message to edge layer: " << Message_to_S2 << std::endl;
            send(clientSocket1, Message_to_S2, strlen(Message_to_S2), 0);
            break;
        }
    }

}

int main() {
    server();
    // cout<<nodes_selected(5,3);
    return 0;
}
