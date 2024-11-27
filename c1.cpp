#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <thread>
#include <bits/stdc++.h>
#include <iostream>
#include <openssl/sha.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <climits>

#include <openssl/hmac.h>
#include <openssl/evp.h>

#define PORT 8080
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

// int r=898998;
int id_gl=1;
    int id_node=1;
    int id_grp=1;
vector<int> secret_share;
vector<int> token;

int LTK=13212;

void assignshare(){
    secret_share={5000332,232344};
}
void calc_token(int r){
    token.push_back(f(r,secret_share[0]));
    token.push_back(f(r,secret_share[1]));
    // cout<<token[0]<<"token"<<token[1]<<endl;
}

std::string getCurrentTime() {
    // Get the current time as a time point
    auto now = std::chrono::system_clock::now();

    // Convert time point to time_t (which represents the number of seconds since the epoch)
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);

    // Convert time_t to a struct tm for local time
    std::tm* local_time = std::localtime(&now_c);

    // Create a string in the format DDMMYYYYHHMM
    char buffer[15]; // 14 characters + 1 for null terminator
    std::strftime(buffer, sizeof(buffer), "%d%m%Y%H%M", local_time);

    return std::string(buffer); // Return as string
}

std::vector<std::string> split (const std::string &s, char delim) {
    std::vector<std::string> result;
    std::stringstream ss (s);
    std::string item;

    while (getline (ss, item, delim)) {
        result.push_back (item);
    }

    return result;
}

string first_message;
vector<string> my_y;
vector<string> my_x;
string publish_share(int id_gl=1,int id_grp=1,int id_node=1,string message="898998/1/2932-2175-9599-2403/d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2"){
    first_message=message;
    vector<string> splitted=split(split(message,'/')[2],'-');
    int r=stoi(split(message,'/')[0]);
    // cout<<"random"<<r<<endl;
    assignshare();
    calc_token(r);
    // vector<string> splitted=split(message,'/');

    // for(auto itr:splitted){cout<<itr<<endl;}
    string temp=getCurrentTime();
    string s=to_string(id_gl)+"/"+to_string(id_grp)+"/"+to_string(id_node)+"/"+temp+"/"+splitted[2*id_node-2]+"/"+splitted[2*id_node-1]+
    "/"+sha256(temp+to_string(id_node)+to_string(token[0])+to_string(token[1]));

    my_y.push_back(splitted[2*id_node-2]);
    my_y.push_back(splitted[2*id_node-1]);
    my_x.push_back(to_string(token[0]));
    my_x.push_back(to_string(token[1]));



    return s;
}

string publish_if_selected(int id_node,int id_gl,int id_grp,string imessage="1-3/111020241247/32823e72783101bb7a46250af05c693ffd35179a82729d3df3defc626ad2cf24"){
    string selected_nodes=split(imessage,'/')[0];
    vector<string> nodes=split(selected_nodes,'-');
    string s="";
    for(auto itr:nodes){
        // cout<<itr<<endl;
        if(itr==to_string(id_node)){
            s=to_string(id_gl)+"/"+to_string(id_grp)+"/"+to_string(id_node)+"/"+to_string(token[0])+"/"+split(split(first_message,'/')[2],'-')[0]; //when you are sending your pair you can send any one
        }
    }
    // cout<<"string is "<<s<<endl;
    return s;
}

void receiveMessages(int socket) {
    char buffer[BUFFER_SIZE];
    while (true) {
        memset(buffer, 0, BUFFER_SIZE);
        int bytesRead = read(socket, buffer, BUFFER_SIZE);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::cout << "Received: " << buffer << std::endl;
        }
    }
}

int result1=111;
double lagrangeInterpolation(const std::vector<int>& x, const std::vector<int>& y, int x_val) {
    double result = 0.0;
    int n = x.size();
    
    // Lagrange Interpolation Formula
    for (int i = 0; i < n; i++) {
        double term = y[i]; // y_i term
        
        for (int j = 0; j < n; j++) {
            if (i != j) {
                term = term * (x_val - x[j]) / (x[i] - x[j]);
            }
        }
        
        result += term;
    }
    
    return result1;
}

std::string toHexString(const unsigned char* data, size_t length) {
    std::stringstream ss;
    for (size_t i = 0; i < length; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
    }
    return ss.str();
}

// Function to generate HMAC using SHA-256
std::string generateHMAC(const std::string& key, const std::string& message) {
    // Define the output buffer
    unsigned char* result;
    unsigned int len = SHA256_DIGEST_LENGTH;

    // Create a buffer to store the HMAC result
    result = (unsigned char*)malloc(len);

    // Generate the HMAC using SHA-256
    HMAC_CTX* ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key.c_str(), key.length(), EVP_sha256(), nullptr);
    HMAC_Update(ctx, (unsigned char*)message.c_str(), message.length());
    HMAC_Final(ctx, result, &len);
    HMAC_CTX_free(ctx);

    // Convert the result to a hex string for readability
    std::string macTag = toHexString(result, len);

    free(result);
    return macTag;
}

void client() {
    int clientSocket;
    struct sockaddr_in serverAddr;
    char buffer[BUFFER_SIZE];

    // Create socket
    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket < 0) {
        std::cerr << "Socket creation error\n";
        exit(EXIT_FAILURE);
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");  // Assuming local server

    // Connect to server
    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        std::cerr << "Connection failed\n";
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to server\n";


    // while (true) {
    //     std::cout << "Enter message (or 'broadcast' to send to all): ";
    //     std::cin.getline(buffer, BUFFER_SIZE);
    //     if (strncmp(buffer, "Send1 ", 6) == 0) {
    //                     // Extract the actual message after "S2"
    //                     const char* Message_to_S2 = buffer + 3;
    //                     std::cout << "message to edge layer: " << Message_to_S2 << std::endl;
    //                     send(clientSocket, Message_to_S2, strlen(Message_to_S2), 0);
    //         }
    //     send(clientSocket, buffer, strlen(buffer), 0);
    // }

/*here first client will receive the global broadcast from S3 that GL got*/
        memset(buffer, 0, BUFFER_SIZE);
        int bytesRead = read(clientSocket, buffer, BUFFER_SIZE);
        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            std::cout << "Received: " << buffer << std::endl;
            string message(buffer);
            /*after receiving that it will compute its local ones and then broadcast its info*/
            string s=publish_share(id_gl,id_grp,id_node,message);
            // s="broadcast "+s;
            const char * temp=s.c_str();
            send(clientSocket, temp, strlen(temp), 0);
        }

int flag=0; //to check if client has been selected or not
/*after the GL receives the broadcast info from everyone it will select t-1 ppl and broadcast their IDs so that they can send their pairs*/
        memset(buffer, 0, BUFFER_SIZE);
        int bytesRead1 = read(clientSocket, buffer, BUFFER_SIZE);
        if (bytesRead1 > 0) {
            buffer[bytesRead1] = '\0';
            std::cout << "Received: " << buffer << std::endl;
            string message(buffer);
            /*Clients check if their ID is present in the list if present then the client will publish their pairs*/
            string s=publish_if_selected(id_node,id_gl,id_grp,message);
                // cout<<s<<endl;
            if(s!=""){
                flag=1;
                s="broadcast "+s;
                const char * temp=s.c_str();
                send(clientSocket, temp, strlen(temp), 0);
            }
            
        }
        int t=2;
        // flag==1?t=2:t=3; //ie if flag is 1 then it will lrecive from 1 less client because itself shared a pair

        vector<string> received_y;
        vector<string> received_x;
        while (t-1>0) {
            memset(buffer, 0, BUFFER_SIZE);
             bytesRead1 = read(clientSocket, buffer, BUFFER_SIZE);
            if (bytesRead1 > 0) {
                buffer[bytesRead1] = '\0';
                std::cout << "Received: " << buffer << std::endl;
                string message(buffer);
                vector<string> temp=split(message,'/');
                received_y.push_back(temp[temp.size()-1]);
                received_x.push_back(temp[temp.size()-2]);
            }
            t--;
        }
        vector<int> x,y;
        for(int i=0;i<received_x.size();i++){
            cout<<received_x[i]<<" "<<received_y[i]<<endl;
            x.push_back(stoi(received_x[i]));
            y.push_back(stoi(received_y[i]));
        }
        for(int i=0;i<my_x.size();i++){
            cout<<my_x[i]<<" "<<my_y[i]<<endl;
            x.push_back(stoi(my_x[i]));
            y.push_back(stoi(my_y[i]));
        }
        int d0=lagrangeInterpolation(x,y,0);
        int Sk=f(d0,LTK);
        string mac_id=generateHMAC(to_string(Sk),to_string(id_node));

        mac_id="macid "+to_string(id_node)+"/"+mac_id;
        const char * temp1=mac_id.c_str();
        send(clientSocket, temp1, strlen(temp1), 0);


    // std::thread receiver(receiveMessages, clientSocket);  // Start a thread for receiving messages so that it receives the pairs from others
    // receiver.join();
    close(clientSocket);
}

int main() {
    // assignshare();
    // calc_token();
    client();
    
    // string message="898998/1/2932-2175-9599-2403/d17f25ecfbcc7857f7bebea469308be0b2580943e96d13a3ad98a13675c4bfc2";

    // cout<<getCurrentTime();
    // cout<<publish_share(token,id_gl,id_grp,id_node,message);
    // cout<<publish_if_selected(id_node,id_gl,id_grp);
    return 0;
}
