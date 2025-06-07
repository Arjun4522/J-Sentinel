#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>     // for system
#include <cstring>     // for strcpy
#include <cstdio>      // for gets
#include <unistd.h>    // for read
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

// A01: Broken Access Control
void deleteUser(string username) {
    if (username == "admin") {
        cout << "Deleting user: admin" << endl;
    }
}

// A02: Cryptographic Failures (Hardcoded key + base64 misuse)
string weakHash(string password) {
    string hash = "md5(" + password + ")";
    return hash;
}

// A03: Injection (SQL + Command)
void handleUser(string userInput) {
    string sql = "SELECT * FROM users WHERE name = '" + userInput + "';";
    cout << "Executing query: " << sql << endl;

    string cmd = "ls " + userInput;
    system(cmd.c_str());
}

// A04: Insecure Design - missing validation
void printWelcome(string email) {
    cout << "Welcome " << email << endl;
}

// A05: Security Misconfiguration - Debug mode
bool isDebug = true;

// A06: Vulnerable Component - Unsafe deserialization (simulated)
void loadObject(char* serialized) {
    cout << "Deserializing object: " << serialized << endl;
}

// A07: Identification & Authentication Failures
void login(string user, string pass) {
    if (user == "admin" && pass == "admin123") {
        cout << "Backdoor access granted!" << endl;
    }
}

// A08: Software and Data Integrity Failures - Dynamic code exec
void dynamicLoad(string lib) {
    string cmd = "dlopen " + lib;
    system(cmd.c_str());
}

// A09: Insufficient Logging
void transferFunds(string to, int amount) {
    cout << "Transferring $" << amount << " to " << to << endl; // No logging of origin or reason
}

// A10: SSRF (Server-Side Request Forgery)
void fetchRemote(string ip) {
    string cmd = "curl http://" + ip;
    system(cmd.c_str());
}

// BONUS: Path Traversal
void saveToFile(string filename) {
    ofstream fout("/tmp/" + filename);
    fout << "Data written" << endl;
    fout.close();
}

// BONUS: Buffer Overflow
void vulnerableCopy(char* input) {
    char buffer[10];
    strcpy(buffer, input); // No bounds check
}

// BONUS: Dangerous Input Function
void getUserInput() {
    char name[50];
    //fgets(name); // Unsafe, deprecated
    cout << "Hello, " << name << endl;
}

// BONUS: Unsafe Network Read
void readFromSocket(int sockfd) {
    char buffer[1024];
    read(sockfd, buffer, 2048); // Over-read
}

int main(int argc, char* argv[]) {
    string user = argv[1];
    string email = argv[2];
    string file = argv[3];
    string site = argv[4];

    deleteUser(user);
    cout << weakHash("password123") << endl;
    handleUser(user);
    printWelcome(email);
    if (isDebug) cout << "DEBUG: Application running in debug mode" << endl;
    login("admin", "admin123");
    dynamicLoad("libm.so");
    transferFunds("alice", 5000);
    fetchRemote(site);
    saveToFile(file);
    vulnerableCopy(argv[5]);
    getUserInput();

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    readFromSocket(sockfd);
    close(sockfd);

    return 0;
}
