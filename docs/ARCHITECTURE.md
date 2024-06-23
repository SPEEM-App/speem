
### Overall Architecture Overview

#### Components:
1. **Rust Shared Library**
   - Handles core functionalities like encryption, key management, and P2P communication.
2. **iOS Application**
   - Built with Swift and SwiftUI.
   - Integrates with the Rust library for core functionalities.
3. **Android Application**
   - Built with Kotlin and Jetpack Compose.
   - Integrates with the Rust library for core functionalities.
4. **Local Storage**
   - Uses SQLCipher for encrypted local storage of messages and keys.

### Component Interaction

#### 1. User Registration and Key Generation
   - **Rust Library**: Generates public/private key pairs.
   - **Mobile Apps**: Invoke the Rust library for key generation and securely store the keys locally.

#### 2. User Pairing via QR Code
   - **Mobile Apps**: Generate and scan QR codes to exchange public keys.
   - **Rust Library**: Stores paired user's public keys securely.

#### 3. Message Encryption and Decryption
   - **Rust Library**: Encrypts messages before sending and decrypts messages upon receiving.
   - **Mobile Apps**: Use Rust library functions for encryption and decryption.

#### 4. Peer-to-Peer Messaging
   - **Rust Library**: Handles P2P communication and ensures messages are transmitted securely.
   - **Mobile Apps**: Establish P2P connections using Rust library and handle message display and notifications.

#### 5. Local Storage and State Management
   - **Local Storage**: Stores encrypted messages, keys, and other relevant data.
   - **Mobile Apps**: Manage state using local storage and ensure data is synchronized with the Rust library.

### Data Flow

1. **Registration**:
   - User registers and Rust library generates key pairs.
   - Keys are stored locally in encrypted storage.

2. **Pairing**:
   - User generates QR code containing their public key.
   - Another user scans the QR code to add the public key to their trusted contacts.
   - Public keys are stored securely.

3. **Messaging**:
   - User composes a message.
   - Rust library encrypts the message using the recipient's public key.
   - Message is sent via P2P connection.
   - Recipient's Rust library decrypts the message.
   - Message is displayed in the app and stored locally in encrypted form.

### Detailed Descriptions

#### Diagram 1: Overall Architecture

<p align="center">
    <img src="assets/overall-architecture.png" width="400" alt="Overall architecture">
</p>

#### Diagram 2: Data Flow

<p align="center">
    <img src="assets/data-flow.png" width="400" alt="Data flow">
</p>

### Data Store and State Management

<p align="center">
    <img src="assets/data-store.png" width="400" alt="Data store">
</p >

### Summary

1. **Rust Shared Library**: Central component for cryptographic operations and P2P messaging, used by both mobile apps.
2. **Mobile Applications**: iOS and Android apps with platform-specific UI, integrating with the Rust library.
3. **Local Storage**: Encrypted storage using SQLCipher to securely store user data, keys, and messages.
4. **Data Flow**: Secure end-to-end data flow from registration and key generation to message encryption, transmission, and storage.
5. **State Management**: Managed locally on the device with secure access through the Rust library.
