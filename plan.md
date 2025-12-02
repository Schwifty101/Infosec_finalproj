# Secure E2E Encrypted Messaging & File-Sharing System - Development Plan

## 1. Project Overview

**Description**: Design and develop a secure communication system that provides end-to-end encryption (E2EE) for text messaging and file sharing where the server cannot decrypt or view any user content.

**Technology Stack**:

- Framework: Next.js (single project for frontend and backend)
- Client-side: Web Crypto API (SubtleCrypto), IndexedDB
- Server-side: Next.js API Routes, MongoDB
- Security Tools: Wireshark, BurpSuite, OpenSSL CLI

**Key Constraints**:

- All encryption must occur client-side
- Private keys must never leave the client device
- No third-party E2EE libraries (Signal, Libsodium, OpenPGP.js)
- Must implement 70% of cryptographic logic ourselves
- Only Web Crypto API allowed for cryptography
- All communication must use HTTPS

---

## 2. Core Requirements (Mandatory)

### 2.1 User Authentication & Key Storage

#### 2.1.1 User Registration & Authentication

- [x] **Implement user registration system** - COMPLETED 2025-12-01
  - Description: Create user accounts with username + password
  - Implementation Notes:
    - Use bcrypt or argon2 for password hashing ✓
    - Implement salting for each password ✓
    - Store hashed passwords securely in MongoDB ✓
  - Acceptance Criteria:
    - Users can register with unique usernames ✓
    - Passwords are never stored in plaintext ✓
    - Salt is unique per user ✓
  - Dependencies: MongoDB setup ✓

#### 2.1.2 Asymmetric Key Pair Generation

- [x] **Generate RSA/ECC key pairs on registration** - COMPLETED 2025-12-01
  - Description: Each user generates asymmetric key pair (ECC P-256)
  - Implementation Notes:
    - Use Web Crypto API's `generateKey()` method ✓
    - Chose ECDSA P-256 for signatures ✓
    - Generate keys during registration process ✓
  - Acceptance Criteria:
    - Key pair generated successfully on client-side ✓
    - Public key can be extracted and sent to server ✓
    - Private key remains on client only ✓
  - Dependencies: User registration completed ✓

#### 2.1.3 Secure Private Key Storage

- [x] **Implement secure client-side key storage** - COMPLETED 2025-12-01
  - Description: Store private keys securely on client device only
  - Implementation Notes:
    - Use IndexedDB for key storage ✓
    - Keys stored with userId as index ✓
    - Implement key extraction and storage using SubtleCrypto ✓
    - Justification documented in lib/crypto/keyStorage.ts ✓
  - Acceptance Criteria:
    - Private keys never sent to server ✓
    - Keys persist across browser sessions ✓
    - Keys are retrievable for encryption/decryption operations ✓
  - Dependencies: Key generation completed ✓

#### 2.1.4 Public Key Distribution

- [x] **Implement public key server storage and retrieval** - COMPLETED 2025-12-01
  - Description: Store public keys on server and allow users to retrieve others' public keys
  - Implementation Notes:
    - Create Next.js API route: POST /api/keys (store public key) ✓
    - Create Next.js API route: GET /api/keys/:userId (retrieve public key) ✓
    - Store public keys in MongoDB associated with user IDs ✓
  - Acceptance Criteria:
    - Public keys stored on server ✓
    - Users can retrieve any other user's public key ✓
    - Public key retrieval works before message exchange ✓
  - Dependencies: User authentication ✓

---

### 2.2 Secure Key Exchange Protocol

#### 2.2.1 Design Custom Key Exchange Protocol

- [x] **Design and document custom key exchange protocol** - COMPLETED 2025-12-02
  - Description: Design unique variant of DH/ECDH key exchange with signatures
  - Implementation Notes:
    - Use ECDH or DH for key agreement
    - Add digital signature mechanism for authentication
    - Implement HKDF or SHA-256 for session key derivation
    - Include key confirmation message
    - Document complete protocol flow with diagrams
    - Ensure protocol prevents MITM attacks
  - Acceptance Criteria:
    - Protocol uses DH/ECDH
    - Includes digital signatures for authentication
    - Derives session key using HKDF/SHA-256
    - Has key confirmation step
    - Complete message flow diagram created
    - Protocol is unique to your group
  - Dependencies: Understanding of DH/ECDH and signatures

#### 2.2.2 Implement Key Exchange Protocol

- [x] **Implement the designed key exchange protocol** - COMPLETED 2025-12-02
  - Description: Code the key exchange protocol on client-side
  - Implementation Notes:
    - Implement each protocol message as separate function
    - Use Web Crypto API for ECDH operations
    - Implement signature generation and verification
    - Store derived session keys securely
  - Acceptance Criteria:
    - Two users can successfully perform key exchange
    - Session key is derived and stored
    - Signatures are verified successfully
    - MITM attacks are prevented
  - Dependencies: Protocol design completed

#### 2.2.3 Session Key Management

- [x] **Implement session key storage and rotation** - COMPLETED 2025-12-02
  - Description: Manage session keys for each conversation
  - Implementation Notes:
    - Store session keys in IndexedDB mapped to conversation ID
    - Implement key rotation logic (optional but recommended)
    - Clear old session keys after expiration
  - Acceptance Criteria:
    - Each conversation has unique session key
    - Session keys retrievable for encryption/decryption
    - Keys properly cleaned up when no longer needed
  - Dependencies: Key exchange implemented

---

### 2.3 End-to-End Message Encryption

#### 2.3.1 Implement Message Encryption

- [x] **Implement AES-256-GCM message encryption** - COMPLETED 2025-12-02
  - Description: Encrypt all messages client-side before sending
  - Implementation Notes:
    - Use AES-256-GCM mode only (no CBC, no ECB)
    - Generate fresh random IV for each message
    - Include authentication tag
    - Use session key for encryption
  - Acceptance Criteria:
    - Messages encrypted with AES-256-GCM ✓
    - Each message has unique IV ✓
    - Authentication tag generated and attached ✓
    - No plaintext sent to server ✓
  - Dependencies: Session key established ✓

#### 2.3.2 Implement Message Decryption

- [x] **Implement client-side message decryption** - COMPLETED 2025-12-02
  - Description: Decrypt received messages on client-side
  - Implementation Notes:
    - Retrieve session key from storage
    - Extract IV and ciphertext from message
    - Verify authentication tag before decryption
    - Handle decryption failures gracefully
  - Acceptance Criteria:
    - Receiver can decrypt messages successfully ✓
    - Authentication tag verified ✓
    - Decryption failures handled with error messages ✓
  - Dependencies: Message encryption implemented ✓

#### 2.3.3 Message Storage Schema

- [x] **Design and implement encrypted message storage** - COMPLETED 2025-12-02
  - Description: Store encrypted messages on server
  - Implementation Notes:
    - Store: ciphertext, IV, sender ID, receiver ID, timestamp, auth tag
    - Never store plaintext message content
    - Create MongoDB schema for messages
  - Acceptance Criteria:
    - Server stores only encrypted data ✓
    - All metadata properly indexed ✓
    - Messages retrievable by conversation ✓
  - Dependencies: Database setup ✓

#### 2.3.4 Build Messaging UI

- [x] **Create user interface for encrypted messaging** - COMPLETED 2025-12-02
  - Description: Build chat interface with message send/receive
  - Implementation Notes:
    - Display decrypted messages in chat window
    - Show encryption status indicators
    - Handle message loading and real-time updates
  - Acceptance Criteria:
    - Users can send and receive encrypted messages ✓
    - Messages display correctly after decryption ✓
    - UI indicates encryption status ✓
  - Dependencies: Encryption/decryption implemented ✓

---

### 2.4 End-to-End File Encryption

#### 2.4.1 Implement File Encryption

- [x] **Implement client-side file encryption** - COMPLETED 2025-12-02
  - Description: Encrypt files before uploading to server
  - Implementation Notes:
    - Read file as ArrayBuffer ✓
    - Encrypt using AES-256-GCM with session key ✓
    - Generate fresh IV for file ✓
    - 50MB file size limit with chunked support ✓
  - Acceptance Criteria:
    - Files encrypted completely before upload ✓
    - Each file has unique IV ✓
    - Large files handled efficiently ✓
    - No plaintext file data sent to server ✓
  - Dependencies: Session key established ✓

#### 2.4.2 Implement File Upload

- [x] **Create encrypted file upload system** - COMPLETED 2025-12-02
  - Description: Upload encrypted files to server
  - Implementation Notes:
    - Create Next.js API route: POST /api/files/upload ✓
    - Store encrypted file data in MongoDB ✓
    - Store metadata: filename, size, IV, sender, receiver ✓
    - Generate unique file ID ✓
  - Acceptance Criteria:
    - Encrypted files uploaded successfully ✓
    - Server stores only encrypted data ✓
    - Metadata properly stored ✓
  - Dependencies: File encryption implemented ✓

#### 2.4.3 Implement File Download & Decryption

- [x] **Create file download and decryption system** - COMPLETED 2025-12-02
  - Description: Download and decrypt files on client-side
  - Implementation Notes:
    - Create Next.js API route: GET /api/files/download/:fileId ✓
    - Retrieve encrypted file and metadata ✓
    - Decrypt file using session key and IV ✓
    - Trigger browser download of decrypted file ✓
  - Acceptance Criteria:
    - Users can download shared files ✓
    - Files decrypted successfully on client ✓
    - Original filename preserved ✓
  - Dependencies: File upload implemented ✓

---

### 2.5 Security Features

#### 2.5.1 Replay Attack Protection - Nonces

- [x] **Implement nonce-based replay protection** - COMPLETED 2025-12-02
  - Description: Generate and verify nonces for each message
  - Implementation Notes:
    - Generate cryptographically random nonce per message
    - Include nonce in message structure
    - Store used nonces server-side (with TTL)
    - Reject messages with duplicate nonces
  - Acceptance Criteria:
    - Each message has unique nonce ✓
    - Duplicate nonces rejected ✓
    - Old nonces expire after reasonable time ✓ (24-hour TTL)
  - Dependencies: Message encryption implemented ✓

#### 2.5.2 Replay Attack Protection - Timestamps

- [x] **Implement timestamp verification** - COMPLETED 2025-12-02
  - Description: Add and verify timestamps on all messages
  - Implementation Notes:
    - Include timestamp in encrypted message payload
    - Verify timestamp on server (within acceptable window)
    - Reject messages with old timestamps
    - Define acceptable time window (e.g., 5 minutes)
  - Acceptance Criteria:
    - All messages timestamped ✓
    - Old messages rejected ✓ (5-minute window)
    - Timestamp verification logged ✓
  - Dependencies: Message encryption implemented ✓

#### 2.5.3 Replay Attack Protection - Sequence Numbers

- [x] **Implement message sequence numbers** - COMPLETED 2025-12-02
  - Description: Add sequence counters per conversation
  - Implementation Notes:
    - Maintain sequence counter per conversation
    - Increment counter for each sent message
    - Verify sequential ordering on receive
    - Reject out-of-order messages
  - Acceptance Criteria:
    - Messages numbered sequentially ✓
    - Out-of-order messages detected and rejected ✓
    - Sequence state maintained per conversation ✓
  - Dependencies: Message encryption implemented ✓

#### 2.5.4 Replay Attack Demonstration

- [ ] **Demonstrate replay attack and mitigation**
  - Description: Show working replay attack and how protections prevent it
  - Implementation Notes:
    - Capture encrypted message using Wireshark
    - Attempt to replay captured message
    - Show rejection due to nonce/timestamp/sequence check
    - Document with screenshots and logs
  - Acceptance Criteria:
    - Replay attack demonstrated successfully
    - Protection mechanisms shown working
    - Complete documentation with evidence
  - Dependencies: All replay protections implemented

---

### 2.6 MITM Attack Demonstration

#### 2.6.1 Demonstrate Vulnerable Key Exchange

- [ ] **Show MITM attack on unsigned DH**
  - Description: Demonstrate MITM attack on DH without signatures
  - Implementation Notes:
    - Create vulnerable version without signatures
    - Use attacker script or BurpSuite to intercept
    - Show attacker can read/modify messages
    - Document complete attack flow
  - Acceptance Criteria:
    - MITM attack successfully demonstrated
    - Attacker can decrypt messages
    - Complete documentation with screenshots
  - Dependencies: Basic DH implemented

#### 2.6.2 Demonstrate MITM Prevention

- [ ] **Show how signatures prevent MITM**
  - Description: Demonstrate that digital signatures prevent MITM
  - Implementation Notes:
    - Use final protocol with signatures
    - Attempt same MITM attack
    - Show signature verification failing
    - Document why attack fails
  - Acceptance Criteria:
    - MITM attack fails with signatures
    - Signature verification prevents attack
    - Complete documentation with comparison
  - Dependencies: Full protocol with signatures implemented

---

### 2.7 Logging & Security Auditing

#### 2.7.1 Implement Authentication Logging

- [x] **Log all authentication attempts** - COMPLETED 2025-12-02
  - Description: Track login attempts (success/failure)
  - Implementation Notes:
    - Log username, timestamp, IP, success/failure
    - Store logs in separate collection
    - Include rate limiting for failed attempts
  - Acceptance Criteria:
    - All auth attempts logged
    - Failed attempts clearly marked
    - Logs include relevant metadata
  - Dependencies: Authentication system

#### 2.7.2 Implement Key Exchange Logging

- [x] **Log key exchange attempts** - COMPLETED 2025-12-02
  - Description: Track all key exchange operations
  - Implementation Notes:
    - Log user pairs, timestamp, success/failure
    - Log signature verification results
    - Store session key IDs (not the keys themselves)
  - Acceptance Criteria:
    - All key exchanges logged
    - Signature verification status logged
  - Dependencies: Key exchange implemented

#### 2.7.3 Implement Decryption Failure Logging

- [x] **Log failed decryption attempts** - COMPLETED 2025-12-03
  - Description: Track when message decryption fails
  - Implementation Notes:
    - Log message ID, user, timestamp, error type ✓
    - Track authentication tag failures ✓
    - Don't log message content ✓
  - Acceptance Criteria:
    - Decryption failures logged ✓
    - Error types captured ✓
  - Dependencies: Encryption/decryption implemented ✓

#### 2.7.4 Implement Security Event Logging

- [x] **Log detected attacks and suspicious activity** - COMPLETED 2025-12-02
  - Description: Track replay attacks, invalid signatures, etc.
  - Implementation Notes:
    - Log duplicate nonces ✓
    - Log expired timestamps ✓
    - Log sequence violations ✓
    - Log invalid signature attempts (partial)
  - Acceptance Criteria:
    - Security events clearly logged ✓
    - Attack attempts identifiable from logs ✓
  - Dependencies: Security features implemented ✓

#### 2.7.5 Create Log Viewing Interface

- [x] **Build interface to view security logs** - COMPLETED 2025-12-03
  - Description: Admin panel to view logs
  - Implementation Notes:
    - Filter by log type ✓
    - Search by user/timestamp ✓
    - Export logs for report (CSV export) ✓
  - Acceptance Criteria:
    - Logs viewable in interface ✓
    - Filtering and search work ✓
  - Dependencies: Logging implemented ✓

---

### 2.8 Threat Modeling

#### 2.8.1 Conduct STRIDE Analysis

- [x] **Perform STRIDE threat modeling** - COMPLETED 2025-12-03
  - Description: Identify threats using STRIDE methodology
  - Implementation Notes:
    - Spoofing threats: authentication weaknesses ✓
    - Tampering threats: message/file modification ✓
    - Repudiation threats: non-repudiation mechanisms ✓
    - Information Disclosure: encryption vulnerabilities ✓
    - Denial of Service: rate limiting needs ✓
    - Elevation of Privilege: access control issues ✓
  - Acceptance Criteria:
    - All STRIDE categories analyzed ✓
    - Threats identified and documented ✓
    - Severity ratings assigned ✓
  - Documentation: `/docs/threat-model/STRIDE_ANALYSIS.md`
  - Dependencies: System understanding ✓

#### 2.8.2 Map Threats to Defenses

- [x] **Map identified threats to implemented countermeasures** - COMPLETED 2025-12-03
  - Description: Show how system defends against each threat
  - Implementation Notes:
    - Create threat-defense mapping table ✓
    - Explain how each defense works ✓
    - Identify any remaining vulnerabilities ✓
  - Acceptance Criteria:
    - Each threat has corresponding defense ✓
    - Mapping clearly documented ✓
    - Gaps identified if any ✓
  - Documentation: `/docs/threat-model/THREAT_DEFENSE_MAPPING.md`
  - Dependencies: STRIDE analysis ✓, system implementation ✓

#### 2.8.3 Document Vulnerable Components

- [x] **Identify and document system vulnerabilities** - COMPLETED 2025-12-03
  - Description: Honest assessment of remaining weaknesses
  - Implementation Notes:
    - Identify components with partial protections ✓
    - Document known limitations ✓
    - Suggest future improvements ✓
  - Acceptance Criteria:
    - Vulnerabilities honestly documented ✓
    - Limitations explained ✓
    - Improvement suggestions provided ✓
  - Documentation: `/docs/threat-model/VULNERABILITIES.md`
  - Dependencies: System implementation ✓

---

### 2.9 System Architecture & Documentation

#### 2.9.1 Create Architecture Diagrams

- [x] **Design and document system architecture** - COMPLETED 2025-12-03
  - Description: High-level architecture diagram
  - Implementation Notes:
    - Client-server architecture ✓
    - Component breakdown ✓
    - Data flow diagrams ✓
    - Used Mermaid for diagrams (GitHub-compatible) ✓
  - Acceptance Criteria:
    - Complete architecture diagram created ✓
    - All components labeled ✓
    - Data flow clearly shown ✓
  - Documentation: `/docs/architecture/SYSTEM_ARCHITECTURE.md`
  - Dependencies: System design ✓

#### 2.9.2 Document Key Exchange Protocol

- [x] **Create detailed protocol flow diagrams** - COMPLETED 2025-12-03
  - Description: Visual representation of key exchange
  - Implementation Notes:
    - Show each message in protocol ✓
    - Label cryptographic operations ✓
    - Show signature verification points ✓
    - Include timing/sequence information ✓
  - Acceptance Criteria:
    - Complete protocol diagram created ✓
    - All steps clearly labeled ✓
    - Easy to understand flow ✓
  - Documentation: `/docs/architecture/PROTOCOL_FLOWS.md`
  - Dependencies: Protocol design ✓

#### 2.9.3 Document Encryption/Decryption Workflows

- [x] **Create encryption workflow diagrams** - COMPLETED 2025-12-03
  - Description: Show message and file encryption flows
  - Implementation Notes:
    - Separate diagrams for message and file encryption ✓
    - Show key selection, IV generation, encryption, storage ✓
    - Include decryption flow ✓
  - Acceptance Criteria:
    - Clear workflow diagrams created ✓
    - Both encryption and decryption shown ✓
  - Documentation: `/docs/architecture/PROTOCOL_FLOWS.md`
  - Dependencies: Implementation completed ✓

#### 2.9.4 Create Database Schema Documentation

- [x] **Document MongoDB schemas** - COMPLETED 2025-12-03
  - Description: Document all database collections and schemas
  - Implementation Notes:
    - Users collection schema ✓
    - Messages collection schema ✓
    - Files collection schema ✓
    - Logs collection schema ✓
  - Acceptance Criteria:
    - All schemas documented ✓
    - Field types and constraints shown ✓
    - Indexes documented ✓
  - Documentation: `/docs/database/SCHEMA_DOCUMENTATION.md`
  - Dependencies: Database implementation ✓

#### 2.9.5 Write Deployment Documentation

- [x] **Create setup and deployment guide** - COMPLETED 2025-12-03
  - Description: Instructions for setting up the system
  - Implementation Notes:
    - Environment setup steps ✓
    - Dependencies installation ✓
    - Configuration requirements ✓
    - Running instructions (local/cloud) ✓
  - Acceptance Criteria:
    - Complete setup instructions ✓
    - Dependencies listed ✓
    - Step-by-step deployment guide ✓
  - Documentation: `/docs/DEPLOYMENT_GUIDE.md`
  - Dependencies: System completed ✓

---

## 3. Bonus Requirements (Optional)

#### 3.1 Two-Factor Authentication

- [ ] **Implement 2FA for user accounts**
  - Description: Add TOTP-based 2FA
  - Implementation Notes:
    - Use time-based OTP (TOTP)
    - Generate QR codes for authenticator apps
    - Store 2FA secrets securely
  - Acceptance Criteria:
    - Users can enable 2FA
    - Login requires 2FA code when enabled

#### 3.2 Advanced UI/UX Features

- [ ] **Add enhanced user interface features**
  - Description: Improve user experience
  - Implementation Notes:
    - Real-time typing indicators
    - Read receipts (encrypted)
    - Message reactions
    - Profile pictures
  - Acceptance Criteria:
    - Features work smoothly
    - Don't compromise security

#### 3.3 Performance Optimizations

- [ ] **Optimize encryption/decryption performance**
  - Description: Improve system performance
  - Implementation Notes:
    - Web Workers for encryption operations
    - File chunking for large files
    - Message pagination
    - Lazy loading
  - Acceptance Criteria:
    - Noticeable performance improvement
    - Large files handled efficiently

#### 3.4 Additional Security Features

- [ ] **Implement extra security mechanisms**
  - Description: Beyond minimum requirements
  - Implementation Notes:
    - Perfect forward secrecy
    - Key rotation mechanisms
    - Self-destructing messages
    - Screenshot detection
  - Acceptance Criteria:
    - Features properly implemented
    - Security properly analyzed

---

## 4. Development Notes

### Critical Dependencies

1. Complete user authentication before key generation
2. Complete key exchange before message encryption
3. Complete message encryption before implementing files
4. Complete all security features before attack demonstrations
5. Complete implementation before threat modeling

### Testing Checkpoints

- After authentication: Test user registration and login
- After key exchange: Verify session key establishment
- After message encryption: Test end-to-end message flow
- After replay protection: Verify attack prevention
- After MITM demo: Verify signature-based prevention
- Before submission: Complete system integration test

### Security Validation Points

- Verify private keys never reach server
- Verify no plaintext stored or transmitted
- Verify all encryption uses AES-256-GCM
- Verify IVs are unique per message
- Verify timestamps and nonces working
- Verify signature verification functioning
- Verify logs capture security events

---

## 5. Project Timeline Suggestion

**Week 1-2**: Authentication, Key Generation, Storage
**Week 3-4**: Key Exchange Protocol Design & Implementation
**Week 5-6**: Message Encryption & Decryption
**Week 7**: File Encryption & Sharing
**Week 8**: Security Features (Replay & MITM)
**Week 9**: Logging & Auditing
**Week 10**: Threat Modeling & Documentation
**Week 11**: Attack Demonstrations
**Week 12**: Testing, Bug Fixes, Report Writing
**Week 13**: Video Demo & Final Submission

---

## References

See `DEVELOPMENTRULES.md` for complete project requirements and constraints.
See `workdone.md` for tracking completed work and progress.
