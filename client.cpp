#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <mutex>
#include <cassert>
#include <mpg123.h>
#include <ncurses.h>
#include <portaudio.h>
using namespace std;

#define PORT 412123
#define MAX_BUFFER 4096

WINDOW* chat_win;
WINDOW* input_win;
mutex print_mutex;

struct Audio {
    char* buffer;
    size_t size;
    size_t offset;
    int channels;
};

struct AudioFormat {
    long rate;
    int channels;
    int encoding;
};

void SSL_init();
SSL_CTX* create_context();
bool signup(SSL* ssl);
bool login(SSL* ssl);
void send_relay_message(SSL* ssl);
void send_file(SSL* ssl);
void receive_file(SSL* ssl);
void send_audio(SSL* ssl);
bool decode_MP3(const char* mp3_file, const char* pcm_file, AudioFormat& format);
void receive_and_play_audio(SSL* ssl);
void display_message(const string& message);
void receive_messages(SSL* ssl);
void client_actions(SSL* ssl);

void SSL_init() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

SSL_CTX* create_context() {
    const SSL_METHOD* method = TLS_client_method();
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void display_message(const string& message) {
    lock_guard<mutex> lock(print_mutex);
    
    // Get window dimensions
    int max_y, max_x;
    getmaxyx(chat_win, max_y, max_x);
    
    // Static variable to track the current line for messages
    static int current_y = 1; // Start at line 1
    
    // Set color
    wattron(chat_win, COLOR_PAIR(1));
    
    // Print the message at (current_y, 2)
    mvwprintw(chat_win, current_y, 2, "%s", message.c_str());
    wattroff(chat_win, COLOR_PAIR(1));
    wrefresh(chat_win);
    
    // Move to the next line
    current_y++;
    
    // If the current line exceeds the window height, scroll the window
    if (current_y >= max_y - 1) { // Leave the last line for the border
        wscrl(chat_win, 1); // Scroll up by one line
        current_y = max_y - 2; // Reset to the last writable line
    }
}

void send_relay_message(SSL* ssl) {
    string receiver, message;

    // Prompt for receiver
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "Enter receiver:");
    wrefresh(input_win);
    wmove(input_win, 1, 17);
    echo();
    char receiver_c[256];
    wgetnstr(input_win, receiver_c, 255);
    noecho();
    receiver = string(receiver_c);

    // Prompt for message
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "Enter message:");
    wrefresh(input_win);
    wmove(input_win, 1, 16);
    echo();
    char message_c[1024];
    wgetnstr(input_win, message_c, 1023);
    noecho();
    message = string(message_c);

    // Send "sendto" command
    if (SSL_write(ssl, "sendto", 6) <= 0) {
        display_message("Failed to send command.");
        return;
    }

    // Send receiver
    if (SSL_write(ssl, receiver.c_str(), receiver.length()) <= 0) {
        display_message("Failed to send receiver.");
        return;
    }

    // Send message
    if (SSL_write(ssl, message.c_str(), message.length()) <= 0) {
        display_message("Failed to send message.");
        return;
    }

    // Display sent message in chat window
    display_message("You to " + receiver + ": " + message);

    // Read server response
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        display_message("Failed to read server response.");
        return;
    }
    buffer[bytes_read] = '\0';
    display_message(string(buffer));
}

void receive_messages(SSL* ssl) {
    // cout << "entered receive_messages" << endl;
    char buffer[MAX_BUFFER];
    memset(buffer, 0, sizeof(buffer));
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0) {
        display_message("Disconnected from server.");
        // break;
    }
    buffer[bytes_received] = '\0';
    display_message(string(buffer));
}

void send_file(SSL* ssl) {
    string file_name;
    // Prompt for file name
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter file name to send: ");
    wrefresh(input_win);
    wmove(input_win, 1, 27);
    echo();
    char file_name_c[256];
    wgetnstr(input_win, file_name_c, 255);
    noecho();
    file_name = string(file_name_c);

    ifstream file(file_name, ios::binary);
    if (!file) {
        display_message("Error opening file.");
        return;
    }

    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, ios::beg);

    // Send "send_file" command
    if (SSL_write(ssl, "send_file", 9) <= 0) {
        display_message("Failed to send send_file command.");
        return;
    }

    // Send file name
    if (SSL_write(ssl, file_name.c_str(), file_name.length()) <= 0) {
        display_message("Failed to send file name.");
        return;
    }

    // Send file size
    string file_size_str = to_string(file_size);
    if (SSL_write(ssl, file_size_str.c_str(), file_size_str.length()) <= 0) {
        display_message("Failed to send file size.");
        return;
    }

    // Send file data
    char buffer[MAX_BUFFER];
    size_t total_size = 0;
    while (total_size < file_size) {
        memset(buffer, 0, MAX_BUFFER);
        int bytes_read = file.read(buffer, MAX_BUFFER).gcount();
        if (bytes_read <= 0) {
            break;
        }
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            display_message("Failed to send file data.");
            return;
        }
        total_size += bytes_read;
    }
    file.close();

    if (total_size == file_size) {
        display_message("File sent successfully.");
    } else {
        display_message("Error sending file.");
    }
}

void receive_file(SSL* ssl) {
    string old_file_name, new_file_name;

    // Prompt for existing file name
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "Enter name of file to receive:");
    wrefresh(input_win);
    wmove(input_win, 1, 32);
    echo();
    char old_file_name_c[256];
    wgetnstr(input_win, old_file_name_c, 255);
    noecho();
    old_file_name = string(old_file_name_c);

    // Prompt for new file name
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter new file name: ");
    wrefresh(input_win);
    wmove(input_win, 1, 23);
    echo();
    char new_file_name_c[256];
    wgetnstr(input_win, new_file_name_c, 255);
    noecho();
    new_file_name = string(new_file_name_c);

    // Send "receive_file" command
    if (SSL_write(ssl, "receive_file", 12) <= 0) {
        display_message("Failed to send receive_file command.");
        return;
    }

    // Send old file name
    if (SSL_write(ssl, old_file_name.c_str(), old_file_name.length()) <= 0) {
        display_message("Failed to send file name.");
        return;
    }

    display_message("File name sent.");

    // Read file size from server
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        // cout << "bytes_read: " << bytes_read << endl;
        display_message("Failed to receive file size.");
        return;
    }
    size_t file_size = stoul(string(buffer, bytes_read));

    // Receive file data
    ofstream file(new_file_name, ios::binary);
    if (!file) {
        display_message("Error opening file for writing.");
        return;
    }

    size_t total_size = 0;
    while (total_size < file_size) {
        memset(buffer, 0, MAX_BUFFER);
        int bytes_recv = SSL_read(ssl, buffer, MAX_BUFFER);
        if (bytes_recv <= 0) {
            break;
        }
        file.write(buffer, bytes_recv);
        total_size += bytes_recv;
    }
    file.close();

    if (total_size == file_size) {
        display_message("File received successfully.");
    } else {
        display_message("Error receiving file.");
    }
}

void send_audio(SSL* ssl) {
    string file_name;
    // Prompt for audio file name
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter audio file name to send: ");
    wrefresh(input_win);
    wmove(input_win, 1, 33);
    echo();
    char file_name_c[256];
    wgetnstr(input_win, file_name_c, 255);
    noecho();
    file_name = string(file_name_c);

    ifstream file(file_name, ios::binary);
    if (!file) {
        display_message("Error opening audio file.");
        return;
    }

    file.seekg(0, ios::end);
    size_t file_size = file.tellg();
    file.seekg(0, ios::beg);

    // Send "send_audio" command
    if (SSL_write(ssl, "send_audio", 10) <= 0) {
        display_message("Failed to send send_audio command.");
        return;
    }

    // Send file name
    if (SSL_write(ssl, file_name.c_str(), file_name.length()) <= 0) {
        display_message("Failed to send audio file name.");
        return;
    }

    // Send file size
    string file_size_str = to_string(file_size);
    if (SSL_write(ssl, file_size_str.c_str(), file_size_str.length()) <= 0) {
        display_message("Failed to send audio file size.");
        return;
    }

    // Send file data
    char buffer[MAX_BUFFER];
    size_t total_size = 0;
    while (total_size < file_size) {
        memset(buffer, 0, MAX_BUFFER);
        int bytes_read = file.read(buffer, MAX_BUFFER).gcount();
        if (bytes_read <= 0) {
            break;
        }
        if (SSL_write(ssl, buffer, bytes_read) <= 0) {
            display_message("Failed to send audio data.");
            return;
        }
        total_size += bytes_read;
    }
    file.close();

    if (total_size == file_size) {
        display_message("Audio sent successfully.");
    } else {
        display_message("Error sending audio.");
    }
}

static int audio_callback(
    const void *inputBuffer,
    void *outputBuffer,
    unsigned long framesPerBuffer,
    const PaStreamCallbackTimeInfo* timeInfo,
    PaStreamCallbackFlags statusFlags,
    void *userData
) {
    Audio* audio = static_cast<Audio*>(userData);
    short* out = static_cast<short*>(outputBuffer); // Assuming paInt16 format
    size_t bytesRequested = framesPerBuffer * sizeof(short) * audio->channels;

    if (audio->offset + bytesRequested > audio->size) {
        bytesRequested = audio->size - audio->offset;
    }

    if (bytesRequested > 0) {
        memcpy(out, audio->buffer + audio->offset, bytesRequested);
        // If remaining bytes are less than requested, fill the rest with silence
        if (bytesRequested < framesPerBuffer * sizeof(short) * audio->channels) {
            memset(out + (bytesRequested / sizeof(short)), 0, 
                   (framesPerBuffer * sizeof(short) * audio->channels) - bytesRequested);
            audio->offset += bytesRequested;
            return paComplete;
        }
        audio->offset += bytesRequested;
        return paContinue;
    } else {
        // Fill the output buffer with silence if no data is left
        memset(out, 0, framesPerBuffer * sizeof(short) * audio->channels);
        return paComplete;
    }
}

bool decode_MP3(const char* mp3_file, const char* pcm_file, AudioFormat& format) {
    mpg123_handle *mh = nullptr;
    unsigned char *buffer = nullptr;
    size_t buffer_size = 0;
    size_t done = 0;
    int err = MPG123_OK;
    ofstream pcm_file_stream(pcm_file, ios::binary);

    if (!pcm_file_stream) {
        cerr << "Error opening PCM file for writing.\n";
        return false;
    }

    // Initialize mpg123 library
    if (mpg123_init() != MPG123_OK || (mh = mpg123_new(nullptr, &err)) == nullptr) {
        cerr << "Unable to initialize mpg123: " << mpg123_plain_strerror(err) << endl;
        return false;
    }

    // Open the MP3 file
    if (mpg123_open(mh, mp3_file) != MPG123_OK) {
        cerr << "Error opening MP3 file: " << mpg123_strerror(mh) << endl;
        mpg123_delete(mh);
        return false;
    }

    // Get the PCM format
    if (mpg123_getformat(mh, &format.rate, &format.channels, &format.encoding) != MPG123_OK) {
        cerr << "Error getting MP3 format: " << mpg123_strerror(mh) << endl;
        mpg123_close(mh);
        mpg123_delete(mh);
        return false;
    }

    mpg123_format_none(mh);
    mpg123_format(mh, format.rate, format.channels, format.encoding);

    // Allocate buffer
    buffer_size = mpg123_outblock(mh);
    buffer = (unsigned char*)malloc(buffer_size * sizeof(unsigned char));
    if (buffer == nullptr) {
        cerr << "Unable to allocate memory for buffer.\n";
        mpg123_close(mh);
        mpg123_delete(mh);
        return false;
    }

    // Read and decode the MP3 file
    while (mpg123_read(mh, buffer, buffer_size, &done) == MPG123_OK) {
        pcm_file_stream.write(reinterpret_cast<char*>(buffer), done);
    }

    // Clean up
    free(buffer);
    mpg123_close(mh);
    mpg123_delete(mh);
    mpg123_exit();
    pcm_file_stream.close();

    return true;
}

void receive_and_play_audio(SSL* ssl) {
    string old_file_name, new_file_name;

    // Prompt for existing audio file name
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "Enter name of audio file to receive: ");
    wrefresh(input_win);
    wmove(input_win, 1, 38);
    echo();
    char old_file_name_c[256];
    wgetnstr(input_win, old_file_name_c, 255);
    noecho();
    old_file_name = string(old_file_name_c);

    // Prompt for new file name
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 1, "Enter new file name: ");
    wrefresh(input_win);
    wmove(input_win, 1, 22);
    echo();
    char new_file_name_c[256];
    wgetnstr(input_win, new_file_name_c, 255);
    noecho();
    new_file_name = string(new_file_name_c);

    // Send "receive_audio" command
    if (SSL_write(ssl, "receive_audio", 13) <= 0) {
        display_message("Failed to send receive_audio command.");
        return;
    }

    // Send old audio file name
    if (SSL_write(ssl, old_file_name.c_str(), old_file_name.length()) <= 0) {
        display_message("Failed to send audio file name.");
        return;
    }

    // Read file size from server
    char buffer[MAX_BUFFER];
    memset(buffer, 0, MAX_BUFFER);
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read <= 0) {
        display_message("Failed to receive audio file size.");
        return;
    }
    size_t file_size = stoul(string(buffer, bytes_read));

    // Receive audio file data
    ofstream file(new_file_name, ios::binary);
    if (!file) {
        display_message("Error opening audio file for writing.");
        return;
    }

    size_t total_size = 0;
    while (total_size < file_size) {
        memset(buffer, 0, MAX_BUFFER);
        int bytes_recv = SSL_read(ssl, buffer, MAX_BUFFER);
        if (bytes_recv <= 0) {
            break;
        }
        file.write(buffer, bytes_recv);
        total_size += bytes_recv;
    }
    file.close();

    if (total_size == file_size) {
        display_message("Audio file received successfully.");
    } else {
        display_message("Error receiving audio file.");
        return;
    }
    
    // Decode MP3 to PCM
    string pcm_file = "output.pcm";
    // char* pcmBuffer = nullptr;
    AudioFormat format;
    if (!decode_MP3(new_file_name.c_str(), pcm_file.c_str(), format)) {
        display_message("Error decoding MP3 file.");
        return;
    }

    // Open the PCM file
    ifstream pcm_stream(pcm_file, ios::binary | ios::ate);
    if (!pcm_stream) {
        display_message("Error opening PCM file for reading.");
        return;
    }

    size_t pcm_size = pcm_stream.tellg();
    pcm_stream.seekg(0, ios::beg);

    unsigned char* pcm_buffer = new unsigned char[pcm_size];
    if (!pcm_stream.read(reinterpret_cast<char*>(pcm_buffer), pcm_size)) {
        display_message("Error reading PCM data from file.");
        delete[] pcm_buffer;
        return;
    }
    pcm_stream.close();

    // Initialize PortAudio
    PaError err = Pa_Initialize();
    if (err != paNoError) {
        display_message("Error initializing PortAudio.");
        delete[] pcm_buffer;
        return;
    }

    // Determine sample format
    PaSampleFormat pa_format;
    switch (format.encoding) {
        case MPG123_ENC_SIGNED_16:
            pa_format = paInt16;
            break;
        case MPG123_ENC_SIGNED_8:
            pa_format = paInt8;
            break;
        case MPG123_ENC_FLOAT_32:
            pa_format = paFloat32;
            break;
        default:
            display_message("Unsupported PCM encoding.");
            Pa_Terminate();
            delete[] pcm_buffer;
            return;
    }

    // Setup audio data
    Audio audio_data;
    audio_data.buffer = reinterpret_cast<char*>(pcm_buffer);
    audio_data.size = pcm_size;
    audio_data.offset = 0;
    audio_data.channels = format.channels;

    // Open PortAudio stream using callback
    PaStream* stream;
    err = Pa_OpenDefaultStream(
        &stream,
        0,                  // No input channels
        format.channels,    // Number of output channels
        pa_format,          // Sample format
        format.rate,        // Sample rate
        paFramesPerBufferUnspecified,
        audio_callback,
        &audio_data         // User data
    );
    if (err != paNoError) {
        string error_msg = "Error opening default stream: " + string(Pa_GetErrorText(err));
        display_message(error_msg);
        Pa_Terminate();
        delete[] pcm_buffer;
        return;
    }

    // Start the stream
    err = Pa_StartStream(stream);
    if (err != paNoError) {
        string error_msg = "Error starting stream: " + string(Pa_GetErrorText(err));
        display_message(error_msg);
        Pa_CloseStream(stream);
        Pa_Terminate();
        delete[] pcm_buffer;
        return;
    }

    // Wait until audio is done
    while ((err = Pa_IsStreamActive(stream)) == 1) {
        Pa_Sleep(100);
    }

    if (err < 0) {
        string error_msg = "Error during streaming: " + string(Pa_GetErrorText(err));
        display_message(error_msg);
    }

    // Stop and close the stream
    err = Pa_StopStream(stream);
    if (err != paNoError) {
        string error_msg = "Error stopping stream: " + string(Pa_GetErrorText(err));
        display_message(error_msg);
    }

    err = Pa_CloseStream(stream);
    if (err != paNoError) {
        string error_msg = "Error closing stream: " + string(Pa_GetErrorText(err));
        display_message(error_msg);
    }

    Pa_Terminate();
    delete[] pcm_buffer;
    remove(pcm_file.c_str());

    display_message("Audio played successfully.");
}

bool signup(SSL* ssl) {
    char buffer[MAX_BUFFER];
    string username, password;

    // Prompt for username
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter username: ");
    wrefresh(input_win);
    wmove(input_win, 1, 18);
    echo();
    char username_c[256];
    wgetnstr(input_win, username_c, 255);
    noecho();
    username = string(username_c);

    // Send username
    if (SSL_write(ssl, username.c_str(), username.length()) <= 0) {
        display_message("Failed to send username.");
        return false;
    }

    // Prompt for password
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter password: ");
    wrefresh(input_win);
    wmove(input_win, 1, 18);
    echo();
    char password_c[256];
    wgetnstr(input_win, password_c, 255);
    noecho();
    password = string(password_c);

    // Send password
    if (SSL_write(ssl, password.c_str(), password.length()) <= 0) {
        display_message("Failed to send password.");
        return false;
    }

    // Read server response
    memset(buffer, 0, MAX_BUFFER);
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        string response(buffer);
        display_message(string(buffer));
        if (response.find("successful") != string::npos) {
            return true;
        }
    }
    display_message("Error reading from server.");
    return false;
}

bool login(SSL* ssl) {
    char buffer[MAX_BUFFER];
    string username, password;

    // Prompt for username
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter username: ");
    wrefresh(input_win);
    wmove(input_win, 1, 18);
    echo();
    char username_c[256];
    wgetnstr(input_win, username_c, 255);
    noecho();
    username = string(username_c);

    // Send username
    if (SSL_write(ssl, username.c_str(), username.length()) <= 0) {
        display_message("Failed to send username.");
        return false;
    }

    // Prompt for password
    werase(input_win);
    box(input_win, 0, 0);
    mvwprintw(input_win, 1, 2, "Enter password: ");
    wrefresh(input_win);
    wmove(input_win, 1, 18);
    echo();
    char password_c[256];
    wgetnstr(input_win, password_c, 255);
    noecho();
    password = string(password_c);

    // Send password
    if (SSL_write(ssl, password.c_str(), password.length()) <= 0) {
        display_message("Failed to send password.");
        return false;
    }

    // Read server response
    memset(buffer, 0, MAX_BUFFER);
    int bytes_read = SSL_read(ssl, buffer, MAX_BUFFER - 1);
    if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        string response(buffer);
        display_message(string(buffer));
        if (response.find("successful") != string::npos) {
            return true;
        }
    }
    display_message("Login failed. Please try again.");
    return false;
}

void client_actions(SSL* ssl) {
    while (true) {
        // Display menu
        werase(input_win);
        box(input_win, 0, 0);

        // Title
        mvwprintw(input_win, 1, 2, "--- You're logged in! ---");

        // Menu Items
        mvwprintw(input_win, 2, 2, "1. Send message");
        mvwprintw(input_win, 3, 2, "2. Receive message");
        mvwprintw(input_win, 4, 2, "3. Send file");
        mvwprintw(input_win, 5, 2, "4. Receive file");
        mvwprintw(input_win, 6, 2, "5. Send audio");
        mvwprintw(input_win, 7, 2, "6. Receive and play audio");
        mvwprintw(input_win, 8, 2, "7. Logout");

        // Prompt for command
        mvwprintw(input_win, 9, 2, "Enter command number:");
        wrefresh(input_win);

        // Get user input
        wmove(input_win, 9, 24);
        echo();
        char input_c[10];
        wgetnstr(input_win, input_c, 9);
        noecho();
        string input = string(input_c);

        if (input.empty()) {
            display_message("Invalid input (empty).");
            continue;
        }

        int command = 0;
        try {
            command = stoi(input);
        } catch (const std::invalid_argument&) {
            display_message("Invalid command (not a number).");
            continue;
        } catch (const std::out_of_range&) {
            display_message("Invalid command (out of range).");
            continue;
        }

        switch (command) {
            case 1:
                send_relay_message(ssl);
                break;
            case 2:
                receive_messages(ssl);
                break;
            case 3:
                send_file(ssl);
                break;
            case 4:
                receive_file(ssl);
                break;
            case 5:
                send_audio(ssl);
                break;
            case 6:
                receive_and_play_audio(ssl);
                break;
            case 7:
                if (SSL_write(ssl, "logout", 6) <= 0) {
                    display_message("Failed to send logout command.");
                }
                display_message("Logged out.");
                return;
            default:
                display_message("Invalid command.");
                break;
        }
    }
}

int main() {
    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(1); // Show cursor
    keypad(stdscr, TRUE); // Enable function keys

    start_color();
    init_pair(1, COLOR_GREEN, COLOR_BLACK);
    init_pair(2, COLOR_RED, COLOR_BLACK);

    int height = LINES - 15;
    int width = COLS;
    int input_height = 15;

    // Create windows for chat display and user input
    chat_win = newwin(height, width, 0, 0);
    input_win = newwin(input_height, width, height, 0);

    // Setup chat window
    box(chat_win, 0, 0);
    // mvwprintw(chat_win, 0, 2, " Chat ");
    wrefresh(chat_win);
    wmove(input_win, 1, 2);
    wrefresh(input_win);

    // Setup input window
    box(input_win, 0, 0);
    // mvwprintw(input_win, 1, 1, "Press F1 to exit.");
    wrefresh(input_win);

    // Initialize OpenSSL
    SSL_init();
    SSL_CTX* ctx = create_context();

    // Create socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        display_message("Error creating socket.");
        endwin();
        exit(EXIT_FAILURE);
    }

    // Server address setup
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr) <= 0) {
        display_message("Invalid address/ Address not supported.");
        close(server_socket);
        endwin();
        exit(EXIT_FAILURE);
    }

    // Connect to server
    if (connect(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        display_message("Connection Failed.");
        close(server_socket);
        endwin();
        exit(EXIT_FAILURE);
    }

    // Create SSL structure
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_socket);

    // Perform SSL handshake
    if (SSL_connect(ssl) <= 0) {
        display_message("SSL Connection Failed.");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(server_socket);
        endwin();
        exit(EXIT_FAILURE);
    }

    // list_audio_devices();

    // Display main menu
    while (true) {
        werase(input_win);
        box(input_win, 0, 0);
        mvwprintw(input_win, 1, 2, "--- Main Menu ---");
        mvwprintw(input_win, 2, 2, "1. Signup");
        mvwprintw(input_win, 3, 2, "2. Login");
        mvwprintw(input_win, 4, 2, "Enter command number: ");
        wrefresh(input_win);

        // Get user input
        wmove(input_win, 4, 24);
        echo();
        char input_c[10];
        wgetnstr(input_win, input_c, 9);
        noecho();
        string input = string(input_c);

        if (input.empty()) {
            display_message("Invalid input (empty).");
            continue;
        }

        int command = 0;
        try {
            command = stoi(input);
        } catch (const std::invalid_argument&) {
            display_message("Invalid command (not a number).");
            continue;
        } catch (const std::out_of_range&) {
            display_message("Invalid command (out of range).");
            continue;
        }

        bool logged_in = false;
        switch(command) {
            case 1:
                if (SSL_write(ssl, "signup", 6) <= 0) {
                    display_message("Failed to send signup command.");
                    break;
                }
                if (signup(ssl)) {
                    display_message("Signup successful. You can now login.");
                } else {
                    display_message("Signup failed.");
                }
                break;
            case 2:
                if (SSL_write(ssl, "login", 5) <= 0) {
                    display_message("Failed to send login command.");
                    break;
                }
                if (login(ssl)) {
                    display_message("Logged in successfully.");
                    // Start handling client actions
                    client_actions(ssl);
                    logged_in = true;
                }
                break;
            default:
                display_message("Invalid command.");
                break;
        }

        if (logged_in)
            break;
    }

    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server_socket);
    SSL_CTX_free(ctx);
    endwin();
    return 0;
}
