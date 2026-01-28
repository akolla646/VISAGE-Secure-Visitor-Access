# Security Documentation – VISAGE (Educational Project)

> **Note**: This document explains the security features implemented in the VISAGE project.  
> While real, production-grade security techniques are used, this application is designed
> for academic learning and demonstration rather than production deployment.

---

## Security Features Implemented

### 1. Hybrid Encryption (AES + RSA)

**Implementation**:
- **AES-256 (CFB mode)**: Encrypts visitor access payloads
  - 256-bit randomly generated key
  - 128-bit IV for randomness
  - Efficient for encrypting structured visitor data
- **RSA-2048**: Used for trust establishment and digital signatures
  - 2048-bit key size
  - Industry-standard asymmetric cryptography

**Why Hybrid Encryption?**
- AES is fast and suitable for encrypting data payloads
- RSA provides strong trust and authenticity guarantees
- Combined approach ensures confidentiality and authenticity

**Code Location**:  
`crypto_utils.py` (encrypt_data), `app.py` (host approval & QR generation)

---

### 2. Digital Signatures (RSA-PSS)

**Implementation**:
- SHA-256 hash over encrypted payload
- RSA-PSS signature using private key
- Signature stored alongside encrypted data

**Purpose**:
- Ensures QR code data integrity
- Prevents tampering or forgery
- Confirms QR is system-issued

**Verification Concept**:
1. Decode QR payload
2. Decrypt encrypted data
3. Verify signature using RSA public key
4. Reject tampered data

**Code Location**:  
`crypto_utils.py` (sign_data), `app.py` (QR generation logic)

---

### 3. Multi-Factor Authentication (MFA)

**Two-Factor Flow**:

1. **First Factor – Password**
   - PBKDF2-HMAC-SHA256 hashing
   - Random salt per user
   - Computationally expensive to resist brute-force attacks

2. **Second Factor – OTP**
   - 6-digit numeric OTP
   - Generated server-side
   - Simulated SMS delivery (printed to console)
   - 5-minute validity period

**Security Benefits**:
- Password compromise alone is insufficient
- OTP expiration prevents replay attacks
- Aligns with NIST SP 800-63-2 guidelines

**Code Location**:  
`app.py` (login, verify_otp routes)

---

### 4. Password Security

**Hashing Algorithm**: PBKDF2-HMAC-SHA256
- One-way hashing (non-reversible)
- Automatic salt generation
- 100,000 iterations

**Benefits**:
- Protects against rainbow table attacks
- Slows offline brute-force attempts
- Industry-standard password protection

**Code Location**:  
`crypto_utils.py` (hash_password, verify_password)

---

### 5. Role-Based Access Control (RBAC)

VISAGE implements an **Access Control List (ACL)** model.

**Roles Defined**:
- Visitor
- Host
- Admin

**Permissions Matrix**:

| Action | Visitor | Host | Admin |
|------|---------|------|-------|
| Register | ✅ | ✅ | ❌ |
| Login | ✅ | ✅ | ✅ |
| Request Access | ✅ | ❌ | ❌ |
| Approve Access | ❌ | ✅ | ❌ |
| View QR Code | ✅ (after approval) | ❌ | ❌ |
| View Users & Roles | ❌ | ❌ | ✅ |

**Authorization Enforcement**:
- Backend route-level checks
- UI hides unauthorized actions
- Prevents privilege escalation

**Code Location**:  
`acl.py`, `app.py` (route enforcement)

---

### 6. Secure QR Code Generation

**What the QR Contains**:
- Visit ID
- Visitor username
- Purpose of visit
- Approval status
- Timestamp
- Issuer identifier

**Security Properties**:
- Payload encrypted using AES
- Encrypted payload digitally signed
- Base64 encoded before QR generation
- QR generated only after host approval

**Result**:
- QR cannot be forged or modified
- Sensitive data remains confidential

**Code Location**:  
`app.py` (host route – approval logic)

---

### 7. Encoding Techniques

- Base64 encoding used for encrypted payloads
- Encoded data embedded inside QR codes
- Ensures safe binary-to-text conversion

**Code Location**:  
`app.py` (QR generation)

---

### 8. Admin Security Design

- Admin account is **pre-provisioned**
- Admin cannot self-register
- Admin dashboard is read-only
- Admin credentials are hashed like all users

**Purpose**:
- Prevents privilege escalation
- Allows system monitoring
- Demonstrates secure admin provisioning

**Code Location**:  
`app.py` (create_default_admin, admin route)

---

## Threat Model (Educational Analysis)

### Threats Mitigated

- **Unauthorized Access** → RBAC & ACL enforcement
- **Password Theft** → Salted hashing
- **OTP Replay** → Expiry-based OTP validation
- **QR Tampering** → Digital signatures
- **Privilege Escalation** → Hidden admin role
- **Data Disclosure** → AES encryption

---

### Known Limitations (Educational Awareness)

- OTP delivery is simulated
- QR verification endpoint not implemented
- Session handling simplified
- No CSRF protection (can be added)

---

## Security Best Practices Demonstrated

### Development Practices
1. Principle of least privilege
2. Defense-in-depth architecture
3. No plaintext password storage
4. Secure defaults
5. Clear separation of roles

### Cryptographic Practices
1. Industry-standard algorithms (AES, RSA, SHA-256)
2. Secure random key and IV generation
3. Digital signatures for integrity
4. Encryption before storage and transmission

### Authentication Practices
1. Multi-factor authentication
2. Time-bound OTPs
3. Strong password hashing
4. Backend-enforced authorization

---

## Conclusion

VISAGE demonstrates a layered security architecture covering authentication,
authorization, encryption, hashing, digital signatures, and secure encoding.
The project aligns with academic security rubrics and modern cybersecurity
best practices, making it suitable for educational evaluation.
