#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <map>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cassert>
using namespace std;

#define PORT 412123
#define MAX_CLIENTS 10
#define MAX_BUFFER 4096
#define USER_DATABASE "users.txt"

unordered_map<int, SSL*> online_clients;
unordered_map<int, string> online_usernames;
mutex client_mutex;

unordered_map<string, string> file_database;
mutex file_db_mutex;

mutex user_db_mutex;

class User {
public:
    void signup(SSL* ssl, int clientSd);
    bool login(SSL* ssl, int clientSd);
};

void SSL_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX* ctx) {
    // Enable ECDH for key exchange
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // Set the certificate
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set the private key
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        cerr << "Private key does not match the public certificate.\n";
        exit(EXIT_FAILURE);
    }
}

void User::signup(SSL* ssl, int clientSd) {
    string entered_username, entered_password;
    char buffer[MAX_BUFFER];

    // Read username
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read username from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    entered_username = string(buffer);
    cout << "[DEBUG] entered_username: " << entered_username << endl;

    // Read password
    memset(buffer, 0, MAX_BUFFER);
    bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read password from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    entered_password = string(buffer);
    cout << "[DEBUG] entered_password: " << entered_password << endl;

    // Lock user database for reading and writing
    lock_guard<mutex> lock(user_db_mutex);

    // Check if username already exists
    ifstream infile(USER_DATABASE);
    string line;
    while (getline(infile, line)) {
        istringstream iss(line);
        string username, password;
        iss >> username >> password;
        if (username == entered_username) {
            string response = "Username already exists.";
            SSL_write(ssl, response.c_str(), response.length());
            cout << "[DEBUG] Signup failed: Username already exists." << endl;
            return;
        }
    }
    infile.close();

    // Append new user to the database
    ofstream outfile(USER_DATABASE, ios::app);
    if (!outfile.is_open()) {
        string response = "Error writing to user database.";
        SSL_write(ssl, response.c_str(), response.length());
        cerr << "[ERROR] Failed to open user database for writing." << endl;
        return;
    }
    outfile << entered_username << " " << entered_password << endl;
    outfile.close();

    // Send success response
    string response = "Signup successful!";
    SSL_write(ssl, response.c_str(), response.length());
    cout << "[DEBUG] Signup successful for user: " << entered_username << endl;
}

bool User::login(SSL* ssl, int clientSd) {
    string entered_username, entered_password;
    char buffer[MAX_BUFFER];

    // Read username
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read username from client " << clientSd << endl;
        return false;
    }
    buffer[bytes_read] = '\0';
    entered_username = string(buffer);
    cout << "[DEBUG] entered_username: " << entered_username << endl;

    // Read password
    memset(buffer, 0, MAX_BUFFER);
    bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read password from client " << clientSd << endl;
        return false;
    }
    buffer[bytes_read] = '\0';
    entered_password = string(buffer);
    cout << "[DEBUG] entered_password: " << entered_password << endl;

    // Lock user database for reading
    lock_guard<mutex> lock(user_db_mutex);

    ifstream infile(USER_DATABASE);
    string line;
    while (getline(infile, line)) {
        istringstream iss(line);
        string username, password;
        iss >> username >> password;
        if (username == entered_username && password == entered_password) {
            infile.close();

            // Lock client data structures
            {
                lock_guard<mutex> client_lock(client_mutex);
                online_clients[clientSd] = ssl;
                online_usernames[clientSd] = entered_username;
            }

            // Send success response
            string response = "Login successful!";
            SSL_write(ssl, response.c_str(), response.length());
            cout << "[DEBUG] Login successful for user: " << entered_username << endl;
            return true;
        }
    }
    infile.close();

    // Send failure response
    string response = "Login failed. Please try again.";
    SSL_write(ssl, response.c_str(), response.length());
    cout << "[DEBUG] Login failed for username: " << entered_username << endl;
    return false;
}

void send_relay_message(SSL* ssl, int clientSd) {
    string receiver, message;
    bool receiver_online = false;
    char buffer[MAX_BUFFER];

    // Read receiver
    memset(buffer, 0, MAX_BUFFER);
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read receiver from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    receiver = string(buffer);
    cout << "[DEBUG] receiver: " << receiver << endl;

    // Read message
    memset(buffer, 0, MAX_BUFFER);
    bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read message from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    message = string(buffer);
    cout << "[DEBUG] message: " << message << endl;

    string full_message = "Message from " + online_usernames[clientSd] + ": " + message;

    // Find receiver and send message
    {
        lock_guard<mutex> lock(client_mutex);
        for (auto& client : online_usernames) {
            if (client.second == receiver) {
                receiver_online = true;
                SSL_write(online_clients[client.first], full_message.c_str(), full_message.length());
                // cout << "[DEBUG] Message sent to " << receiver << endl;
                break;
            }
        }
    }

    if (!receiver_online) {
        string response = "Receiver is not online.";
        SSL_write(ssl, response.c_str(), response.length());
        cout << "[DEBUG] Receiver is not online." << endl;
    } else {
        string response = "Message sent.";
        SSL_write(ssl, response.c_str(), response.length());
        cout << "[DEBUG] Message sent to " << receiver << endl;
    }
}

void handle_send_file(SSL* ssl, int clientSd) {
    string file_name;
    size_t file_size;
    char buffer[MAX_BUFFER];

    // Read file name
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read file name from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    file_name = string(buffer);
    cout << "[DEBUG] file_name: " << file_name << endl;

    // Read file size
    memset(buffer, 0, MAX_BUFFER);
    bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read file size from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    file_size = stoul(string(buffer, bytes_read));
    cout << "[DEBUG] file_size: " << file_size << endl;

    // Receive file data and save to server
    string server_file_name = "server_" + file_name;

    ofstream file(server_file_name, ios::binary);
    if (!file.is_open()) {
        cerr << "[ERROR] Failed to open file " << server_file_name << " for writing." << endl;
        return;
    }

    size_t total_size = 0;
    while (total_size < file_size) {
        memset(buffer, 0, MAX_BUFFER);
        int recv_bytes = SSL_read(ssl, buffer, MAX_BUFFER);
        if (recv_bytes <= 0) {
            cerr << "[ERROR] Failed to read file data from client " << clientSd << endl;
            file.close();
            return;
        }
        file.write(buffer, recv_bytes);
        total_size += recv_bytes;
    }
    file.close();
    cout << "[DEBUG] File received by server: " << server_file_name << endl;

    // Update file database
    {
        lock_guard<mutex> lock(file_db_mutex);
        file_database[file_name] = server_file_name;
    }

    // Send confirmation to client
    // string response = "File received by server.";
    // SSL_write(ssl, response.c_str(), response.length());
}

void handle_receive_file(SSL* ssl, int clientSd) {
    string file_name;
    char buffer[MAX_BUFFER];

    // Read requested file name
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        cerr << "[ERROR] Failed to read file name from client " << clientSd << endl;
        return;
    }
    buffer[bytes_read] = '\0';
    file_name = string(buffer);
    cout << "[DEBUG] file_name: " << file_name << endl;

    // Find the server file
    string server_file_name;
    {
        lock_guard<mutex> lock(file_db_mutex);
        auto it = file_database.find(file_name);
        if (it != file_database.end()) {
            server_file_name = it->second;
        }
    }

    if (server_file_name.empty()) {
        string response = "File not found on server.";
        SSL_write(ssl, response.c_str(), response.length());
        cout << "[DEBUG] File not found: " << file_name << endl;
        return;
    }

    // Open the server file
    ifstream file(server_file_name, ios::binary);
    if (!file.is_open()) {
        string response = "Error opening file on server.";
        SSL_write(ssl, response.c_str(), response.length());
        cerr << "[ERROR] Failed to open server file: " << server_file_name << endl;
        return;
    }

    cout << "[DEBUG] Sending file: " << server_file_name << endl;

    // Get file size
    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, ios::beg);

    // Send file size
    string file_size_str = to_string(file_size);
    if (SSL_write(ssl, file_size_str.c_str(), file_size_str.length()) <= 0) {
        cerr << "[ERROR] Failed to send file size to client " << clientSd << endl;
        file.close();
        return;
    }
    cout << "[DEBUG] File size sent: " << file_size << endl;

    // Send file data
    size_t total_sent = 0;
    while (total_sent < file_size) {
        memset(buffer, 0, MAX_BUFFER);
        file.read(buffer, MAX_BUFFER);
        int bytes_to_send = file.gcount();
        if (bytes_to_send <= 0)
            break;

        if (SSL_write(ssl, buffer, bytes_to_send) <= 0) {
            cerr << "[ERROR] Failed to send file data to client " << clientSd << endl;
            file.close();
            return;
        }
        total_sent += bytes_to_send;
    }
    file.close();
    cout << "[DEBUG] File sent: " << server_file_name << endl;

    // Send confirmation
    // string response = "File transfer successful.";
    // SSL_write(ssl, response.c_str(), response.length());
}

void handle_send_audio(SSL* ssl, int clientSd) {
    // This function is identical to handle_send_file, but could be extended for audio-specific handling
    handle_send_file(ssl, clientSd);
}

void handle_receive_audio(SSL* ssl, int clientSd, char msg[MAX_BUFFER]) {
    // This function is identical to handle_receive_file, but could be extended for audio-specific handling
    handle_receive_file(ssl, clientSd);
}

void client_handler(int client_socket) {
    char buffer[MAX_BUFFER];
    User user;
    bool logged_in = false;

    SSL* ssl;
    {
        lock_guard<mutex> lock(client_mutex);
        auto it = online_clients.find(client_socket);
        if (it == online_clients.end()) {
            cerr << "[ERROR] SSL not found for client " << client_socket << endl;
            close(client_socket);
            return;
        }
        ssl = it->second;
    }

    while (true) {
        memset(buffer, 0, MAX_BUFFER);
        int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
        if (bytes_read <= 0) {
            cerr << "[DEBUG] Client " << client_socket << " disconnected." << endl;
            break;
        }
        buffer[bytes_read] = '\0';
        string msg = string(buffer);
        cout << "[DEBUG] msg: " << msg << endl;

        if (!logged_in && msg == "signup") {
            user.signup(ssl, client_socket);
        } else if (!logged_in && msg == "login") {
            logged_in = user.login(ssl, client_socket);
        } else if (logged_in && msg == "logout") {
            cout << "[DEBUG] Client " << client_socket << " logged out." << endl;
            break;
        } else if (logged_in && msg == "sendto") {
            send_relay_message(ssl, client_socket);
        } else if (logged_in && msg == "send_file") {
            handle_send_file(ssl, client_socket);
        } else if (logged_in && msg == "receive_file") {
            handle_receive_file(ssl, client_socket);
        } else if (logged_in && msg == "send_audio") {
            handle_send_audio(ssl, client_socket);
        } else if (logged_in && msg == "receive_audio") {
            handle_receive_audio(ssl, client_socket, buffer);
        } else {
            cerr << "[DEBUG] Invalid command from client " << client_socket << ". Closing connection." << endl;
            break;
        }
    }

    // Clean up after client disconnects or logs out
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_socket);

    // Remove client from online_clients and online_usernames
    {
        lock_guard<mutex> lock(client_mutex);
        online_clients.erase(client_socket);
        online_usernames.erase(client_socket);
    }
}

int main(int argc, char *argv[]) {
    // Initialize OpenSSL
    SSL_init();
    SSL_CTX* ctx = create_context();
    configure_context(ctx);

    // Create server socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        cerr << "Error creating server socket.\n";
        exit(EXIT_FAILURE);
    }

    // Allow address reuse
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        cerr << "Error setting socket options.\n";
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Bind socket to the specified port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Listen on all interfaces
    server_addr.sin_port = htons(PORT);

    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        cerr << "Error binding server socket.\n";
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Start listening
    if (listen(server_socket, MAX_CLIENTS) < 0) {
        cerr << "Error listening on server socket.\n";
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    cout << "SSL server has started on port " << PORT << endl;

    // Server loop to accept incoming connections
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);

        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            cerr << "Error accepting client socket.\n";
            continue;
        }

        cout << "Client socket " << client_socket << " connected." << endl;

        // Create SSL structure
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);
        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        {
            lock_guard<mutex> lock(client_mutex);
            online_clients[client_socket] = ssl;
        }

        // Create a thread to handle the client
        thread t(client_handler, client_socket);
        t.detach();
    }

    // Cleanup (unreachable in this code)
    close(server_socket);
    SSL_CTX_free(ctx);
    return 0;
}
