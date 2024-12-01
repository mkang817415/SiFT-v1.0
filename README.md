# Simple File Transfer (SiFT) Protocol Version 1.0

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9.6%2B-blue.svg)

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Generating RSA Keys](#generating-rsa-keys)
- [Usage](#usage)
  - [Running the Server](#running-the-server)
  - [Running the Client](#running-the-client)
  - [Logging In](#logging-in)
  - [Available Commands](#available-commands)
- [Example](#example)
  - [Uploading a File](#uploading-a-file)
- [Authors](#authors)
- [License](#license)

## Overview

The **Simple File Transfer (SiFT)** project is a secure file transfer system designed to allow clients to perform file operations on a server remotely. This implementation covers version **0.5** of the SiFT protocol, which includes non-cryptographic features such as sending commands for file manipulation and uploading/downloading files in smaller pieces. Additionally, the project extends to version **1.0**, incorporating cryptographic protections to ensure secure communication between the client and server.

## Features

- **User Authentication:** Secure login with session key establishment using RSA and AES encryption.
- **File Operations:** Execute commands like `pwd`, `lst`, `chd`, `mkd`, `del`, `upl`, and `dnl` to manage files and directories on the server.
- **Secure Communication:** Implements AES-GCM for encrypted message transfer and protects against replay attacks.
- **File Transfer:** Supports uploading and downloading files in 1024-byte fragments with integrity verification using SHA-256 hashes.
- **Extensible Protocols:** Designed to easily extend or modify protocol features as needed.

## Project Structure
```plaintext
SiFT/
├── specification/
│   ├── SiFT v1.0 specification.md
│   └── Cryptography Project Instructions.txt
├── server/
│   ├── keys/
│   │   └── keypair.pem
│   ├── rsa.py
│   ├── server.py
│   ├── siftprotocols/
│   │   ├── siftcmd.py
│   │   ├── siftdnl.py
│   │   ├── siftlogin.py
│   │   ├── siftmtp.py
│   │   └── siftupl.py
│   ├── users.txt
│   └── users/
│       ├── alice/
│       ├── bob/
│       └── charlie/
├── client/
│   ├── client.py
│   ├── keys/
│   │   └── public_key.pem
│   ├── siftprotocols/
│   │   ├── siftcmd.py
│   │   ├── siftdnl.py
│   │   ├── siftlogin.py
│   │   ├── siftmtp.py
│   │   └── siftupl.py
│   ├── test_1.txt
│   └── test_2.txt
├── README.md
├── requirements.txt
└── LICENSE
```

## Getting Started

### Prerequisites

- **Python 3.8 or higher**
- **pip** (Python package installer)
- **OpenSSL** (for RSA key generation)

### Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/mkang817415/SiFT-v1.0.git
   cd SiFT-v1.0
   ```

### Installation

2. **Install Required Python Packages:**

   It's recommended to use a virtual environment.

   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
    ```

### Generating RSA Keys 
To secure the communication between the client and server, generate an RSA key-pair for the server.  

   ```bash
   cd server
   python3 rsa.py 
   ```

## Usage

### Running the Server

1. **Navigate to Server Directory and Start the Server:**

    ```bash
    cd server 
    python3 server.py
    ```

### Running the Client

1. **Open a New Terminal Window**

2. **Navigate to Client Directory and Start the Client:**

    ```bash
    cd client 
    python3 client.py
    ```
    
### Logging In: 

Upon starting the client, you will be prompted to log in. Use one of the predefined test users:

- alice/aaa
- bob/bbb
- charlie/ccc

#### Example:
    ```plaintext
    Username: alice
    Password: aaa
    ```

### Available Commands

After a successful login, type help to view available commands:

- **pwd**: Print current working directory.
- **lst**: List contents of the current directory.
- **chd [directory]**: Change directory.
- **mkd [directory]**: Make a new directory.
- **del [file/directory]**: Delete a file or directory.
- **upl [filename]**: Upload a file to the server.
- **dnl [filename]**: Download a file from the server.
- **exit**: Close the client.

## Example

### Uploading A File:
1. **Command:**

    ```bash
    upl example.txt
    ```
    
2. **Response:**

   ```bash
   upl
   <request_hash>
   accept
   ```
   
## Authors

- **Your Name** - *Collaborator* - [mkang817415](https://github.com/mkang817415)
- **David Rhoades** - *Collaborator* - [David-Rhoadess](https://github.com/David-Rhoadess)
- **Vagmin Viswanathan** - *Collaborator* - [vagminv](https://github.com/vagminv)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.




