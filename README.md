# cryptographie-coder

**Cryptographie-Coder**

A simple web application built with Python and Flask for encrypting and decrypting text using AES, DES, and RSA algorithms. It provides a user-friendly interface to perform cryptographic operations and view results instantly.

---

## Features

- **AES Encryption/Decryption**: Secure symmetric encryption using AES in CBC mode with PKCS7 padding.
- **DES Encryption/Decryption**: Symmetric encryption using DES in CBC mode with PKCS7 padding.
- **RSA Encryption/Decryption**: Asymmetric encryption using RSA (2048-bit keys) with OAEP padding.
- **Key Management**: Automatic key normalization for AES/DES and on-the-fly RSA key pair generation.
- **Error Handling**: User-friendly flash messages for invalid inputs or operations.
- **Logging**: Built-in debug logging to trace encryption/decryption processes.

---

## Prerequisites

- Python 3.7 or higher
- Flask
- PyCryptodome

---

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/BhlHk/cryptographie-coder.git
   cd cryptographie-coder
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```


## Usage

1. **Run the application**:
   ```bash
   python app.py
   ```
2. **Open your browser** and navigate to `http://localhost:5000/`.
3. **Encrypt Text**:
   - Select **Encrypt** on the home page.
   - Enter your plaintext, choose AES, DES, or RSA, and provide a key (for RSA, omit the key to auto-generate a key pair).
   - View the Base64-encoded ciphertext on the results page.
4. **Decrypt Text**:
   - Navigate to **Decrypt** via the top menu or URL `http://localhost:5000/decrypt`.
   - Paste the Base64 ciphertext, select the algorithm, and enter the correct key or RSA private key.
   - View the decrypted plaintext on the results page.

---



## Security Considerations

- **Session Secret**: Always set a strong `SESSION_SECRET` in production.
- **Key Storage**: Never store plaintext keys in client-side code or logs.
- **HTTPS**: Serve the application over HTTPS to protect data in transit.
- **RSA Key Size**: The application uses 2048-bit keys; consider 3072+ bits for highly sensitive data.

---

## Contributing

1. Fork this repository.
2. Create a feature branch: `git checkout -b feature/YourFeature`.
3. Commit your changes: `git commit -m "Add some feature"`.
4. Push to the branch: `git push origin feature/YourFeature`.
5. Open a Pull Request.


---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

