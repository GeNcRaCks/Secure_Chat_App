Abstract 
This project demonstrates the development of a secure chat application that allows two users to 
communicate safely over a local network. The application uses RSA encryption for secure key 
exchange, AES encryption for securing messages, and SHA-256 hashing for verifying message 
integrity. By combining symmetric and asymmetric encryption, the system ensures confidentiality, 
authenticity, and integrity. The project is implemented in Python and executed through a 
command-line interface. It is intended for educational purposes, allowing students to understand 
practical cryptography. 
Introduction 
Digital communication has become a vital part of everyday life. People share personal, financial, 
and professional information over messaging platforms, emails, and other online channels. While 
these communications are convenient, they are also vulnerable to attacks, such as eavesdropping, 
data tampering, or identity theft. To prevent these issues, messages need to be encrypted before 
transmission. 
Cryptography provides methods to secure messages. It converts readable messages (plaintext) 
into unreadable format (ciphertext) using algorithms and keys. Only authorized recipients with 
the correct key can decrypt and read the original message. 
This project focuses on creating a secure chat application that demonstrates: 
 How RSA is used for key exchange. 
 How AES encrypts actual messages efficiently. 
 How SHA-256 ensures message integrity. 
 Practical implementation in Python for educational understanding. 
The application is designed for local communication between two users, providing a hands-on 
approach to cryptography concepts without the complexity of networking. 
Problem Statement 
Although cryptography is widely taught, most students only learn theory. Few get the chance to 
implement a real-world secure communication system. Without such practical knowledge: 
 Users cannot verify message confidentiality. 
 Understanding of encryption, decryption, and hashing remains abstract. 
 Data can be vulnerable to attackers if security is not applied correctly. 
This project addresses these issues by providing a working secure chat application, 
demonstrating hybrid cryptography, encryption workflows, and message integrity checks. And the 
confidentiality can be checked by using wireshark in Kali Linux. 
Objectives 
1. Develop a Python-based chat application for secure text communication. 
2. Implement RSA encryption for exchanging AES session keys securely. 
3. Implement AES encryption for encrypting messages. 
4. Use SHA-256 hashing for verifying message integrity. 
5. Provide a modular, easy-to-understand Python implementation. 
6. Teach students practical cryptography and secure communication workflows. 
Scope 
The project covers: 
 Local network communication between two users. 
 RSA key generation for each user. 
 AES session key generation for messages. 
 Message encryption and decryption using AES. 
 Secure AES key exchange using RSA. 
 Message integrity verification using SHA-256. 
It does not cover: 
 Networking over the internet. 
 Multimedia files or group chats. 
 User authentication systems. 
 Persistent database storage. 
Literature Review 
Cryptography Basics 
Cryptography is the science of protecting information. Its main goals are: 
 Confidentiality: Prevent unauthorized access. 
 Integrity: Ensure the message is not altered. 
 Authentication: Verify the identity of users. 
 Non-repudiation: Prevent denial of message origin. 
Two primary types of encryptions exist: 
1. Asymmetric Encryption: Uses a public and private key pair. The sender encrypts using 
the recipient’s public key, and only the private key can decrypt it. 
2. Symmetric Encryption: Uses a single shared key for encryption and decryption. It is faster 
but requires secure key exchange. 
RSA Encryption 
RSA (Rivest–Shamir–Adleman) is widely used for key exchange. Its security relies on the 
difficulty of factoring large prime numbers. In the chat application: 
 Each user generates an RSA key pair. 
 The sender encrypts the AES session key with the receiver’s public RSA key. 
 Only the receiver can decrypt the AES key with their private RSA key. 
Example: 
1. Receiver generates keys: Public Key PU, Private Key PR. 
2. Sender encrypts AES key K_AES using PU. 
3. Receiver decrypts K_AES using PR. 
AES Encryption 
AES (Advanced Encryption Standard) is a symmetric encryption algorithm used for encrypting 
the actual messages. AES is fast and secure, suitable for real-time communication. 
Workflow in the project: 
1. Sender generates a random AES session key for each message. 
2. Encrypts the message using AES with that key. 
3. Sends the encrypted message along with the AES key encrypted using RSA. 
Example: 
 Plaintext: "Hello Bob" 
 AES key: randomly generated 32-byte key 
 Ciphertext: unreadable message 
 Receiver decrypts with AES key. 
SHA-256 Hashing 
SHA-256 produces a 256-bit fixed-length hash from any input message. It ensures that even a 
single character change in the message produces a completely different hash. HMAC-SHA256 
uses a secret key with SHA-256 to provide message integrity and authenticity while preventing 
tampering and replay attacks. 
Workflow in the project: 
 Sender computes SHA-256 hash of the message. 
 Receiver computes SHA-256 hash after decryption. 
 If hashes match, message integrity is verified. 
Example: 
 Message: "Hello" 
 SHA-256  
 hash: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969 
 Any modification in "Hello" will produce a different hash. 
System Design 
The system follows a client–server architecture with four logical layers: 
1. GUI Layer – Tkinter-based user interface 
2. Network Layer – TCP socket communication 
3. Integrity Verification Layer 
4. Cryptographic Layer – Modular encryption utilities 
5. Application Logic Layer – Message handling and connection management 
The chat application uses hybrid cryptography: 
1. RSA: For securely exchanging AES keys. 
2. AES: For encrypting messages. 
3. SHA-256: For verifying message integrity. 
Workflow Description 
1. Server starts and listens on a predefined port 
2. Client connects to the server 
3. Server generates RSA-2048 key pair 
4. Public key is transmitted to client 
5. Client generates AES-256 session key 
6. AES key is encrypted using RSA public key 
7. Server decrypts AES key using private key 
8. HMAC key is derived from AES key 
9. Secure communication channel is established 
Implementation in Python 
Required Libraries 
 cryptography: For RSA and AES encryption. 
 hashlib: For SHA-256 hashing. 
 os: For random AES key generation. 
Steps to Run the Script 

1. Run Script: 
2. Install pycryptodome (if missing) 
3. Python3 server_gui.py 
4. Python3 client_gui.py 
5. Follow Prompts: 
o Exchange RSA public keys. 
o Start sending messages. 
o Messages will automatically be encrypted, decrypted, and verified. 


 Tampered Key: Decryption fails if AES key is modified. 
 Tampered Message: SHA-256 mismatch detected. 
 Performance: Encryption and decryption occur in milliseconds for small messages. 
Limitations 
1. Only supports two users over local network. 
2. No internet connectivity or sockets. 
3. Multimedia files are not supported. 
4. Lacks user authentication or database storage. 
5. Advanced attacks not implemented. 
