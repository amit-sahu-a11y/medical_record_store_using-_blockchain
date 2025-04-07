Medical Record Storage System using Blockchain
📌 Overview
This project is a secure, decentralized platform for storing and managing medical records using blockchain technology. It ensures immutability, data privacy, and traceability by combining a custom Python-based blockchain with AES and RSA encryption.

🚀 Key Features
🔐 Secure Storage of medical records

🔗 Blockchain-based tamper-proof architecture

🔑 Dual Encryption using AES (data) and RSA (key)

🧑‍⚕️ User Authentication system for doctors and patients

🌐 Web Interface built with Flask and HTML/CSS

📁 Record Submission & Retrieval with verification

⚙️ Technologies Used
Python

Flask

Custom Blockchain (SHA-256)

RSA & AES Encryption

HTML/CSS (Frontend)

🧠 How It Works
Users log in or register on the platform.

Medical records are submitted through a secure form.

Records are encrypted using AES; the AES key is encrypted using RSA.

A block is created with the encrypted data and stored in the blockchain.

Records can later be decrypted and viewed by authorized users only.

🏗️ System Architecture
User → Web Interface → Encryption Layer → Blockchain

Retrieval → Decryption Layer → Verified Record Display

🔮 Future Enhancements
Public blockchain integration (Ethereum/Hyperledger)

Role-based permissions & patient consent

Smart contracts for automation

Mobile app version

Integration with hospital systems or IoT devices
