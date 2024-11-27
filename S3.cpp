#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <vector>
#include <thread>
#include <bits/stdc++.h>
#include <iostream>
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <climits>

#define PORT 80801
#define MAX_CLIENTS 4
#define BUFFER_SIZE 1024

using namespace std;


vector<vector<int>> secret_shares={{5000332,232344},{242332,80080},{34343,909090}};


/*to implement to algo***********************************************************************/

/*function f *************************************************************************/
unsigned long long hashToInteger(const unsigned char* hash, size_t length) {
    unsigned long long result = 0;
    for (size_t i = 0; i < sizeof(unsigned long long) && i < length; ++i) {
        result = (result << 8) | hash[i];
    }
    return result;
}

std::string intToString(int number) {
    return std::to_string(number);
}

int f(int r, int s,int mod=67890) {
    std::string rStr = intToString(r);
    std::string sStr = intToString(s);

    std::string input = rStr + sStr;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)input.c_str(), input.size(), hash);

    // Convert hash to an integer and return
    return hashToInteger(hash, SHA256_DIGEST_LENGTH)%mod;
}
/*************************************************************************************** */

/*to genrate the polynomial for each group ***************************************************/
// Function to generate a random integer in the range [1, q-1]
int generateRandomCoefficient(int q) {
    static std::mt19937 rng(time(0));  // Random number generator seeded with current time
    std::uniform_int_distribution<int> dist(1, q - 1);  // Range [1, q-1]
    return dist(rng);
}

// Function to generate a (t-1)-degree polynomial d(x) mod q
std::vector<int> generatePolynomial(int t, int d0, int q) {
    std::vector<int> coefficients(t);  // To store the polynomial coefficients

    // Set k0 = d0 (constant term)
    coefficients[0] = d0;

    // Generate random coefficients for k1, k2, ..., k_{t-1} such that 0 < ki < q
    for (int i = 1; i < t; ++i) {
        coefficients[i] = generateRandomCoefficient(q);
    }

    return coefficients;
}

// Function to display the polynomial
void displayPolynomial(const std::vector<int>& coefficients, int q) {
    int t = coefficients.size();
    std::cout << "Polynomial d(x) = ";

    for (int i = 0; i < t; ++i) {
        std::cout << coefficients[i] << " * x^" << i;
        if (i < t - 1) {
            std::cout << " + ";
        }
    }
    std::cout << " mod " << q << std::endl;
}

// Function to evaluate the polynomial at a given x and return the result modulo q
int evaluatePolynomial(const std::vector<int>& coefficients, int x, int q) {
    int result = 0;
    int powerOfX = 1;  
    for (size_t i = 0; i < coefficients.size(); ++i) {
        result = (result + (coefficients[i] * powerOfX) % q) % q;  
        powerOfX = (powerOfX * x) % q;  
    }
    return result;
}
/******************************************************************************************** */

/*to genrate publishing pair*/

vector<vector<int >> publishingpairs(vector<vector<int>> secretshares,int r,int t=3,int d0=11111,int q=10079){
    vector<vector<int >> temp;
    vector<int> coeff=generatePolynomial(t,d0,q);
    displayPolynomial(coeff,q);
    for(auto itr:secretshares){
        int t1=f(r,itr[0]);
        int t2=f(r,itr[1]);
        // cout<<t1<<"jjjj"<<t2<<endl;

        t1=evaluatePolynomial(coeff,t1,q);
        t2=evaluatePolynomial(coeff,t2,q);
        // cout<<t1<<"pppp"<<t2<<endl;

        // cout<<evaluatePolynomial(coeff,0,q)<<"dddd";


        temp.push_back({t1,t2});
    }
    return temp;
}
/***************************** */

/* to generate hash */
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
/****************************** */
// Function to broadcast a message to all clients
void broadcastToClients(int senderSocket, const std::vector<int>& clients, const char* message) {
    for (int clientSocket : clients) {
        if (clientSocket != senderSocket) {  // Don't send to the sender itself
            send(clientSocket, message, strlen(message), 0);
        }
    }
}
int server(string s) {

    int serverSocket, clientSocket, activity;
    struct sockaddr_in serverAddr, clientAddr;
    fd_set readfds;
    char buffer[BUFFER_SIZE];
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
                    std::cout << "Message from S2: " << buffer << std::endl;
                        send(clientSocket, "Message received by S3", 26, 0);
                    }
                }
            }
                /* the AS will not send anything after Auth*/

            // Handle server input
            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                memset(buffer, 0, BUFFER_SIZE);
                std::cin.getline(buffer, BUFFER_SIZE);  // Read input from the server console ie we will just type send so that the pre calculated message will be sent

                    const char* broad=s.c_str();

                    // Server broadcasts the message to all clients
                    std::cout << "Server sending to S2: " << broad << std::endl;
                    broadcastToClients(-1, clients, broad);  // -1 indicates that the server is the sender

            }
        }

}





int main() {
    int r=898998;
    int d0=111;
    int t=3;
    int q=10079;
    string to_broadcast=to_string(r)+"/"+"1"+"/";
    vector<vector<int>> temp=publishingpairs(secret_shares,r,t,d0,q);
    for(int i=0;i<temp.size();i++){
        // cout<<temp[i][0]<<' '<<temp[i][1]<<endl;
        to_broadcast+=to_string(temp[i][0])+"-"+to_string(temp[i][1]);
        if(i!=temp.size()-1){
            to_broadcast+="-";
        }
    }
    to_broadcast+="/"+sha256(to_string(d0));

    server(to_broadcast);

    /*
        the broadcasted message:898998/1/4863-6351-6160-4742/d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2
        here we statically ficed the GL id because ideally the AS should send broadcasst this message multiple times ie once for each GL
    */

    // cout<<to_broadcast<<endl;
    return 0;
}
