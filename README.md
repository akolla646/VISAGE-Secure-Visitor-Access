# VISAGE – Secure Visitor Access & Approval System

A Flask-based secure visitor management system demonstrating enterprise-grade security practices including multi-factor authentication, role-based access control, hybrid encryption (AES + RSA), digital signatures, and QR-code-based access credentials.

## What This Project Demonstrates

### Core Security Concepts
- **Multi-Factor Authentication**: Password + One-Time Password (OTP)
- **Role-Based Access Control**: Visitor, Host, and Admin roles enforced via ACL
- **Hybrid Encryption**: AES-256 for data confidentiality + RSA-2048 for trust and signatures
- **Digital Signatures**: RSA-PSS for integrity and authenticity of QR payloads
- **Secure Password Storage**: PBKDF2-SHA256 with automatic salting
- **Authorization Enforcement**: Access granted only after host approval
- **Secure Encoding**: Base64-encoded encrypted payload embedded in QR codes

### Technologies & Security Features
- **Backend Framework**: Flask (Python)
- **Cryptography**: Python `cryptography` library
- **Password Hashing**: PBKDF2-HMAC with SHA-256
- **OTP Authentication**: 6-digit OTP with expiry (simulated SMS)
- **Database Security**: SQLite with encrypted sensitive data at rest
- **Admin Provisioning**: Pre-registered admin (not exposed in UI)

---

## Quick Start (Local Development)

### Installation

1. **Navigate to the project directory**
   ```bash
   cd VISAGE
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   venv\Scripts\activate    # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Open in browser**
   ```
   http://127.0.0.1:5000
   ```

⚠️ If schema errors occur after updates, delete `database.db` once and restart.

---

## Default Credentials

### Pre-Registered Admin
- **Username**: admin
- **Password**: Admin@123

(Admin account is created automatically and cannot be registered via UI.)

---

## System Architecture

### User Roles & Permissions

| Role | Register | Login | Request Access | Approve Access | View QR | View Users |
|-----|----------|-------|----------------|---------------|---------|------------|
| **Visitor** | ✅ | ✅ | ✅ | ❌ | ✅ (after approval) | ❌ |
| **Host** | ✅ | ✅ | ❌ | ✅ | ❌ | ❌ |
| **Admin** | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |

---

### Security Workflow

1. **Registration**: User registers with email, phone, and password
2. **Login**: Password verified → OTP sent to phone (simulated)
3. **Access Request**: Visitor submits visit purpose
4. **Authorization**: Host approves the request
5. **Credential Issuance**: System generates encrypted & signed QR code
6. **Access Display**: Visitor dashboard shows QR after approval
7. **Monitoring**: Admin dashboard lists all users and roles

---

## Project Structure

```
VISAGE/
├── templates/              # HTML templates (role-based dashboards)
├── static/                 # CSS and generated QR images
├── app.py                  # Main Flask application
├── crypto_utils.py         # Cryptographic utilities (hashing, encryption, signatures)
├── acl.py                  # Access Control List definitions
├── requirements.txt        # Python dependencies
├── database.db             # SQLite database (auto-generated)
├── README.md               # Project overview
└── SECURITY_DOCUMENTATION.md
```

---

## Security Implementation Details

### Encryption (Hybrid AES + RSA)
- Visitor access payload encrypted using AES-256 (CFB mode)
- Encrypted payload digitally signed using RSA-2048 (RSA-PSS)
- Ensures confidentiality, integrity, and authenticity of QR data

### Digital Signatures
- SHA-256 hash over encrypted payload
- RSA-PSS signature scheme
- Prevents QR tampering and forgery

### Authentication & Authorization
- Passwords hashed with PBKDF2-SHA256 and random salt
- 6-digit OTP with 5-minute expiry
- Role-based access enforced via ACL
- Admin role hidden from registration UI

---

## Technologies Used

- **Backend**: Flask
- **Security**: cryptography (AES, RSA, PBKDF2)
- **Database**: SQLite
- **Authentication**: Custom MFA with OTP
- **Frontend**: HTML, CSS (Jinja templates)

---

## Important Notes

⚠️ **Educational Project**  
This project is designed for academic demonstration of cybersecurity concepts. It uses real cryptographic primitives but is optimized for clarity rather than production scale.

🔐 **OTP Delivery**  
OTP is printed to the console for demo purposes. In production, an SMS gateway can be integrated.

📊 **Data Protection**  
All sensitive visitor information embedded in QR codes is encrypted before storage and transmission.

---

## Documentation

- **SECURITY_DOCUMENTATION.md**: Detailed security architecture, threat model, and mitigation strategies
- **Inline Code Comments**: Explain cryptographic and authorization decisions

---

## License

Educational project for demonstrating secure application development practices.

---

**Project Purpose**: Academic demonstration of secure visitor access management using modern cryptography and access control.

**Author**: Akshara K  
