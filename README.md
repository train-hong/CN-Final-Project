# Secure Chatroom Application

## Table of Contents
- [Secure Chatroom Application](#secure-chatroom-application)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Features](#features)
  - [Technologies Used](#technologies-used)
  - [Prerequisites](#prerequisites)
    - [For macOS (using Homebrew)](#for-macos-using-homebrew)
    - [For Debian/Ubuntu-based Linux](#for-debianubuntu-based-linux)
    - [For Fedora](#for-fedora)
  - [Configuration](#configuration)
  - [Compilation](#compilation)
  - [Usage](#usage)
    - [Running the Server](#running-the-server)
    - [Running the Client](#running-the-client)
  - [Project Structure](#project-structure)

## Overview

The **Secure Chatroom Application** is a terminal-based chat system developed in C++ that allows multiple users to communicate securely over a network. It leverages SSL/TLS for encrypted communications, ensuring that messages, files, and audio data are transmitted securely. The client interface is enhanced with `ncurses` to provide an interactive and user-friendly experience.

## Features

- **User Authentication**
  - **Signup:** Create a new user account with a unique username and password.
  - **Login:** Authenticate using existing credentials to access the chatroom.

- **Messaging**
  - **Send Messages:** Communicate with other online users in real-time.
  - **Receive Messages:** Receive messages from other users asynchronously.

- **File Transfer**
  - **Send Files:** Upload files to the server to share with other users.
  - **Receive Files:** Download files shared by other users from the server.

- **Audio Handling**
  - **Send Audio:** Share audio files with other users.
  - **Receive and Play Audio:** Download and play audio files shared by others.

- **Secure Communications**
  - Utilizes SSL/TLS to encrypt all data transmissions between the client and server.

- **User Interface**
  - **Terminal-Based GUI:** Enhanced with `ncurses` for better navigation and display.
  - **Responsive Layout:** Clearly separated sections for chat display and user input.

## Technologies Used

- **Programming Language:** C++
- **Libraries & Frameworks:**
  - [`OpenSSL`](https://www.openssl.org/) for SSL/TLS encryption.
  - [`ncurses`](https://invisible-island.net/ncurses/) for creating a text-based user interface.
  - [`mpg123`](https://www.mpg123.de/) for MP3 decoding.
  - [`PortAudio`](http://www.portaudio.com/) for audio playback.
- **Build System:** Makefile

## Prerequisites

Before building and running the application, ensure that the following dependencies are installed on your system.

### For macOS (using Homebrew)
```bash
brew install openssl ncurses mpg123 portaudio
```

### For Debian/Ubuntu-based Linux
```bash
sudo apt-get update
sudo apt-get install libssl-dev libncurses5-dev libmpg123-dev portaudio19-dev
```

### For Fedora
```bash
sudo dnf install openssl-devel ncurses-devel mpg123-devel portaudio-devel
```

## Configuration

- **User Database:**

  The application uses a simple text file `users.txt` to store user credentials. Ensure that this file exists in the server's root directory. The server will append new users during the signup process.

  ```bash
  touch users.txt
  ```

- **Ports:**

  The server listens on port `412123` by default. Ensure that this port is open and not used by other applications.

## Compilation

The project includes a `Makefile` to streamline the build process. Ensure that all prerequisites are installed before proceeding.

1. **Navigate to the Project Directory:**
   ```bash
   cd path\to\project
   ```

2. **Build the Server and Client:**
   ```bash
   make
   ```
   
   This will compile two executables:
   - `server` — The chat server.
   - `client` — The chat client.

3. **Clean Build Artifacts:**
   
   To remove the compiled binaries, run:
   
   ```bash
   make clean
   ```

## Usage

### Running the Server

1. **Start the Server:**
   ```bash
   ./server
   ```
   
   The server will start listening on port `412123` and will output:
   ```
   SSL server has started on port 412123
   ```

### Running the Client

1. **Start the Client:**
   Open a new terminal window and run:
   ```bash
   ./client 412123
   ```
   
2. **Interact with the Client Interface:**
   
   - **Main Menu:**
     ```
     ┌────────────────────────────────────┐
     │                                    │
     │ --- Main Menu ---                  │
     │ 1. Signup                          │
     │ 2. Login                           │
     │ Enter command number:              │
     │                                    │
     └────────────────────────────────────┘
     ```
   
   - **Signup:**
     - Choose `1` to create a new account.
     - Enter a unique username and password when prompted.
   
   - **Login:**
     - Choose `2` to log in with existing credentials.
     - Upon successful login, access the chat functionalities.
   
   - **Chat Menu:**
     ```
     ┌────────────────────────────────────┐
     │                                    │
     │ --- You're logged in! ---          │
     │ 1. Send message                    │
     │ 2. Receive message                 │
     │ 3. Send file                       │
     │ 4. Receive file                    │
     │ 5. Send audio                      │
     │ 6. Receive and play audio          │
     │ 7. Logout                          │
     │ Enter command number:              │
     │                                    │
     └────────────────────────────────────┘
     ```
   
   - **Sending Messages:**
     - Choose `1` to send a message to another online user.
   
   - **Receiving Messages:**
     - Choose `2` to receive messages from other users.
   
   - **File Operations:**
     - **Send File:** Choose `3` to upload a file to the server.
     - **Receive File:** Choose `4` to download a file from the server.
   
   - **Audio Operations:**
     - **Send Audio:** Choose `5` to upload an audio file to the server.
     - **Receive and Play Audio:** Choose `6` to download and play an audio file from the server.
   
   - **Logout:**
     - Choose `7` to logout from the chatroom.

## Project Structure

```
b11902139/
├── README.md
└── code/
    ├── client.cpp
    ├── server.cpp
    ├── Makefile
    ├── users.txt     # User database
    ├── cert.pem      # SSL certificate
    ├── key.pem       # SSL private key
    ├── a.out         # file to transferred
    ├── song.mp3      # audio to transferred
    └── other files or folders
```
