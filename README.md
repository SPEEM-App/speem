# SPEEM (Serverless Private Encrypted End-to-End Messaging)

///--------- THIS IS A WORK IN PROGRESS ----------///
<p align="center">
    <img src="docs/assets/logo.jpg" width="400" alt="SPEEM logo">
</p>

SPEEM is a highly secure, serverless messaging application designed for maximum privacy. Users can send encrypted messages directly to their trusted contacts without relying on any central servers. The application features end-to-end encryption, secure local storage, and a user-friendly pairing process via QR codes.

## Features

- **End-to-End Encryption**: All messages are encrypted using strong cryptographic algorithms, ensuring that only the intended recipient can read them.
- **Serverless Architecture**: Messages are stored only on users' devices, eliminating the need for central servers.
- **Secure Key Management**: Each user has a unique public/private key pair, securely managed and stored.
- **QR Code Pairing**: Users can easily add trusted contacts by scanning QR codes.
- **Cross-Platform**: Available for both iOS and Android, with a shared Rust library for core cryptographic functions.

## Technical Highlights

SPEEM leverages Rust for its core cryptographic and networking operations, encapsulated in a shared library used by both the iOS and Android applications. This approach was chosen for several reasons:

- **Performance and Safety**: Rust offers memory safety guarantees without a garbage collector, making it an ideal choice for performance-critical and secure applications.
- **Code Reusability**: By using a shared Rust library, we ensure that critical code is written once and reused across both platforms, reducing the potential for bugs and inconsistencies.
- **Cross-Platform Development**: Rust’s ability to compile to native code for both iOS and Android streamlines the development process and ensures that the security and cryptographic features are consistent across platforms.
- **FFI (Foreign Function Interface)**: Rust’s robust FFI support allows seamless integration with Swift on iOS and Kotlin on Android, enabling us to build a unified codebase while leveraging platform-specific features and optimizations.

For more detailed information on the architecture of the project, read the [ARCHITECTURE overview](docs/ARCHITECTURE.md)

## Project Structure

```
SPEEM/
├── rust_lib/                 # Rust shared library
│   ├── src/
│   │   ├── lib.rs
│   │   ├── crypto.rs
│   │   ├── storage.rs
│   │   └── p2p.rs
│   ├── Cargo.toml
│   └── Cargo.lock
├── ios_app/                  # iOS app
│   ├── SPEEM/
│   │   ├── AppDelegate.swift
│   │   ├── ContentView.swift
│   │   ├── QRCodeScanner.swift
│   │   └── ...               # Other SwiftUI views and controllers
│   ├── SPEEM.xcodeproj/
│   ├── rust_lib_bridge/      # Rust to Swift bindings
│   │   ├── rust_lib.h
│   │   └── rust_lib.swift
│   └── ...                   # Other iOS-specific files
├── android_app/              # Android app
│   ├── app/
│   │   ├── src/
│   │   │   ├── main/
│   │   │   │   ├── java/com/cipherchat/
│   │   │   │   │   ├── MainActivity.kt
│   │   │   │   │   └── QRCodeScanner.kt
│   │   │   │   └── jni/     # Rust to Kotlin bindings
│   │   │   │       ├── rust_lib.h
│   │   │   │       └── rust_lib.kt
│   │   ├── build.gradle
│   │   └── ...               # Other Android-specific files
├── scripts/                  # Build and deployment scripts
│   ├── build_rust_lib.sh
│   ├── deploy_ios.sh
│   └── deploy_android.sh
├── tests/                    # Integration and end-to-end tests
│   ├── rust_tests.rs
│   ├── ios_tests.swift
│   └── android_tests.kt
├── docs/                     # Documentation
│   ├── assets/
│   │   ├── logo.png
│   ├── architecture.md
│   ├── setup.md
│   └── usage.md
├── README.md
├── LICENSE
└── .gitignore
```

## Getting Started

### Prerequisites

- Rust and Cargo installed
- Xcode for iOS development
- Android Studio for Android development

### Building the Project

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/wassimans/SPEEM.git
   cd SPEEM
   ```

2. **Build the Rust Library**:
   ```sh
   cd rust_lib
   cargo build --release
   ```

3. **Set Up iOS App**:
   - Open `ios_app/SPEEM.xcodeproj` in Xcode.
   - Configure the project settings as needed.
   - Build and run the project on a simulator or device.

4. **Set Up Android App**:
   - Open `android_app` in Android Studio.
   - Sync the project with Gradle files.
   - Build and run the project on an emulator or device.

## Contributing

TODO

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Thanks to the Rust community for providing excellent resources and support.
- Inspired by privacy-focused communication tools and open-source projects.

## Contact

For any inquiries or issues, please contact me: wassim [at] wassimans [dot] com.
