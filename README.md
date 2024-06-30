
# SPEEM

**Secure Password Encryption and Easy Management**

SPEEM is a secure password manager designed to provide maximum security and ease of use. With SPEEM, your passwords and sensitive information are stored locally on your device, encrypted and accessible only to you. SPEEM eliminates the need for cloud storage, ensuring your data remains under your control.

## Features

- **Local Encryption**: All data is encrypted locally on your device, ensuring maximum security.
- **End-to-End Encryption**: Only you have access to your encrypted data.
- **Device Syncing**: Seamless syncing across your devices via local network or secure peer-to-peer connections.
- **Mnemonic Recovery Phrases**: Secure account recovery using mnemonic phrases.
- **User-Friendly Interface**: Easy to manage and access your passwords.

## Roadmap

We are currently in the development phase, working towards our first version. Our roadmap includes:

### Version 1 (V1)

- Core functionalities including secure password storage, local encryption, and device syncing.

### Future Versions

- Enhancements based on user feedback
- Additional security protocols
- Mobile applications
- More features to provide the best password management experience

## Performance and Usability

At SPEEM, we are committed to providing maximum performance and usability for our users. To achieve this, we have chosen Rust for our core cryptographic and storage functionalities. Rust's memory safety and performance characteristics make it an ideal choice for building secure and efficient applications.

By utilizing Rust for both business logic and the graphical user interface, we ensure that our code is both robust and performant. Additionally, we will develop native applications for major desktop operating systems, followed by mobile apps, to leverage the full capabilities of each platform and provide a seamless user experience.

This approach enables us to combine the best of both worlds: the safety and speed of Rust, along with a user-friendly and performant application.

## Getting Started

### Prerequisites

- Rust (latest stable version)
- Cargo (Rust package manager)
- SQLite
- SQLCipher

### Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/SPEEM-App/speem-app.git
   cd speem-app
   ```

2. Build the project:

   ```bash
   cargo build --release
   ```

3. Run the application:

   ```bash
   cargo run
   ```

### Configuration

SPEEM uses a configuration file (`config.json`) for database setup and other configurations. Make sure to set the `database_url` and `database_passphrase` appropriately.

## Contributing

SPEEM is currently a solo endeavor by [Wassim Mansouri](https://wassimans.com), developed in the [open](https://github.com/SPEEM-App/speem-app). While contributions are not currently being accepted, we plan to open the project for contributions once we are past the V1 milestone.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contact

For more information about the developer, visit [Wassim Mansouri's personal website](https://wassimans.com).

## Acknowledgments

- Inspired by the need for a secure, serverless and private password manager.
- Built with love and passion for privacy and security.

