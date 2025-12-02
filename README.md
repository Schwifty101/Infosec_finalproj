# Secure E2E Encrypted Messaging & File-Sharing System

Academic project for Information Security course implementing custom cryptographic protocols for end-to-end encrypted communication.

## Features Implemented

- ✅ User authentication with bcrypt password hashing
- ✅ Client-side ECC P-256 key pair generation
- ✅ Custom AECDH-ECDSA key exchange protocol (3-message authenticated)
- ✅ End-to-end message encryption (AES-256-GCM)
- ✅ End-to-end file encryption and sharing
- ✅ Replay protection (nonces + timestamps + sequence numbers)
- ✅ TOFU (Trust-On-First-Use) public key validation
- ✅ Security event logging
- ✅ User discovery and conversation management
- 🚧 MITM attack demonstrations (in progress)

## Technology Stack

- **Frontend**: Next.js 15, React, TypeScript, Web Crypto API
- **Backend**: Next.js API Routes, Node.js
- **Database**: MongoDB
- **Cryptography**: Web Crypto API (SubtleCrypto) for all primitives
- **Storage**: IndexedDB for client-side key storage

## Quick Start

### Prerequisites
- Node.js 18+ and npm
- MongoDB (local or Atlas)

### Installation

1. **Clone repository**:
   ```bash
   git clone [repository-url]
   cd finalProj
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Configure environment** (`.env.local`):
   ```env
   MONGODB_URI=mongodb://localhost:27017/secure-messaging
   ```

4. **Run development server**:
   ```bash
   npm run dev
   ```

5. **Open browser**: http://localhost:3000

### Build for production:
```bash
npm run build
npm start
```

## Architecture Overview

### Client-Side Responsibilities
- ALL encryption/decryption operations (messages and files)
- Key generation (ECC P-256 asymmetric pairs)
- Private key storage (IndexedDB)
- Session key management
- Signature generation and verification
- IV generation for each encryption
- Replay attack protection (nonce, timestamp, sequence validation)

### Server-Side Responsibilities
- User authentication (bcrypt password hashing)
- Public key storage and distribution
- Encrypted message/file storage (ciphertext + metadata only)
- Metadata management (sender/receiver IDs, timestamps)
- Security event logging
- **NEVER**: Decrypt content, store private keys, or access plaintext

## API Endpoints

### Authentication
- `POST /api/auth/register` - User registration with key generation
- `POST /api/auth/login` - User login with session creation

### Key Exchange (AECDH-ECDSA Protocol)
- `POST /api/key-exchange/initiate` - Start key exchange (Message 1)
- `POST /api/key-exchange/respond` - Respond to exchange (Message 2)
- `POST /api/key-exchange/confirm` - Confirm mutual agreement (Message 3)
- `GET /api/key-exchange/pending/[userId]` - List pending requests
- `GET /api/key-exchange/status/[sessionId]` - Check exchange status

### Messaging (E2EE)
- `POST /api/messages/send` - Send encrypted message
- `GET /api/messages/conversation/[conversationId]` - Retrieve messages
- `GET /api/messages/sequence/[conversationId]` - Get next sequence number

### File Sharing (E2EE)
- `POST /api/files/upload` - Upload encrypted file
- `GET /api/files/download/[fileId]` - Download encrypted file
- `GET /api/files/conversation/[conversationId]` - List files in conversation

### User Discovery
- `GET /api/users/search` - Search users by username
- `GET /api/keys/[userId]` - Retrieve user's public key

### Conversations
- `GET /api/conversations` - List user's conversations
- `POST /api/conversations` - Create new conversation

### Security
- `POST /api/security/log` - Log security events

## Security Features

### Cryptographic Standards
- **Message/File Encryption**: AES-256-GCM only (no CBC, ECB)
- **Asymmetric Keys**: ECC P-256 (ECDSA for signatures, ECDH for key agreement)
- **IVs**: 12-byte unpredictable IVs, generated per message/file
- **Key Exchange**: Custom AECDH-ECDSA protocol with HKDF-SHA256
- **Session Keys**: AES-256-GCM derived via HKDF
- **Password Storage**: bcrypt with automatic salting

### Security Mechanisms
- **End-to-End Encryption**: Private keys NEVER leave client device
- **Forward Secrecy**: Ephemeral ECDH keys for each exchange
- **MITM Prevention**: ECDSA P-256 signatures on all protocol messages
- **TOFU Pattern**: Public key fingerprint validation prevents key substitution
- **Replay Protection**:
  - Nonces (16 bytes, cryptographically random)
  - Timestamps (5-minute validation window)
  - Sequence numbers (per-conversation counters)
- **Authentication Tags**: GCM tags verified before decryption
- **Secure Storage**: IndexedDB for client-side keys

### Threat Mitigations
- **Replay Attacks**: Nonce uniqueness + timestamp + sequence enforcement
- **MITM Attacks**: Digital signatures on ephemeral keys + TOFU validation
- **Message Tampering**: AES-GCM authentication tags
- **Key Compromise**: Forward secrecy via ephemeral keys
- **Server Compromise**: Server never has plaintext or private keys
- **Parallel Exchanges**: Prevention of simultaneous key exchanges for same user pair

## Key Exchange Protocol (AECDH-ECDSA)

Our custom 3-message authenticated key exchange protocol:

```
1. INIT (Alice → Bob):
   - Generate ephemeral ECDH P-256 key pair
   - Sign ephemeral public key with Alice's ECDSA key
   - Send: { ephemeralPubKey, signature, nonce, timestamp }

2. RESPONSE (Bob → Alice):
   - Verify Alice's signature
   - Generate Bob's ephemeral ECDH key pair
   - Compute shared secret via ECDH
   - Derive session key using HKDF-SHA256
   - Sign ephemeral public key with Bob's ECDSA key
   - Send: { ephemeralPubKey, signature, nonce, timestamp }

3. CONFIRM (Alice → Bob):
   - Verify Bob's signature
   - Compute shared secret via ECDH
   - Derive session key using HKDF-SHA256
   - Compute HMAC confirmation tag
   - Send: { confirmationTag, timestamp }

Bob verifies confirmation tag → Both have identical session key
```

**Security Properties**:
- **Mutual Authentication**: Both parties verify each other's signatures
- **Forward Secrecy**: Ephemeral keys deleted after exchange
- **Replay Protection**: Nonces + timestamps validated
- **MITM Prevention**: Signatures on ephemeral keys prevent substitution
- **Parallel Exchange Prevention**: Only one active exchange allowed per user pair

## Message Encryption Flow

```
Sender (Alice):
1. Retrieve session key from IndexedDB
2. Generate unique IV (12 bytes)
3. Generate nonce (16 bytes)
4. Get next sequence number
5. Create AAD: { nonce, sequenceNumber }
6. Encrypt: AES-256-GCM(sessionKey, plaintext, IV, AAD)
7. Send to server: { ciphertext, IV, authTag, nonce, sequenceNumber }

Server:
1. Validate nonce uniqueness (check MongoDB)
2. Validate timestamp (5-minute window)
3. Validate sequence number (must be next in order)
4. Store encrypted message + metadata
5. Log security events

Receiver (Bob):
1. Fetch encrypted message from server
2. Retrieve session key from IndexedDB
3. Recreate AAD: { nonce, sequenceNumber }
4. Decrypt: AES-256-GCM(sessionKey, ciphertext, IV, AAD)
5. Verify authentication tag (automatic in GCM)
6. Display plaintext
```

## Project Structure

```
finalProj/
├── app/                          # Next.js application
│   ├── api/                      # API routes
│   │   ├── auth/                 # Authentication endpoints
│   │   ├── key-exchange/         # Key exchange protocol endpoints
│   │   ├── messages/             # Messaging endpoints
│   │   ├── files/                # File sharing endpoints
│   │   ├── users/                # User discovery
│   │   ├── conversations/        # Conversation management
│   │   └── security/             # Security logging
│   ├── components/               # React components
│   │   ├── RegisterForm.tsx      # User registration
│   │   ├── LoginForm.tsx         # User login
│   │   ├── KeyExchangeManager.tsx # Key exchange UI
│   │   ├── UserSearch.tsx        # User discovery
│   │   ├── ConversationList.tsx  # Conversation list
│   │   ├── ChatWindow.tsx        # Chat interface
│   │   ├── MessageBubble.tsx     # Message display
│   │   ├── MessageInput.tsx      # Message composition
│   │   └── FileAttachment.tsx    # File handling
│   ├── register/                 # Registration page
│   ├── login/                    # Login page
│   ├── dashboard/                # User dashboard
│   ├── key-exchange/             # Key exchange page
│   └── messaging/                # Messaging page
├── lib/                          # Core libraries
│   ├── crypto/                   # Cryptographic operations
│   │   ├── keyGeneration.ts      # ECC key pair generation
│   │   ├── keyStorage.ts         # IndexedDB storage
│   │   ├── keyValidation.ts      # TOFU pattern implementation
│   │   ├── hkdf.ts               # HKDF key derivation
│   │   ├── keyExchange.ts        # ECDH operations
│   │   ├── signatures.ts         # ECDSA signing/verification
│   │   ├── protocol.ts           # Key exchange orchestration
│   │   ├── sessionKeys.ts        # Session key management
│   │   ├── messaging.ts          # Server-side encryption
│   │   ├── messaging-client.ts   # Client-side encryption
│   │   ├── fileEncryption.ts     # File encryption
│   │   └── utils.ts              # Crypto utilities
│   └── db/                       # Database
│       ├── connection.ts         # MongoDB connection
│       └── models.ts             # Database schemas
├── types/                        # TypeScript definitions
│   ├── index.ts                  # Shared types
│   └── keyExchange.ts            # Protocol types
└── docs/                         # Documentation
    ├── DEVELOPMENTRULES.md       # Project requirements
    ├── plan.md                   # Development roadmap
    └── workdone.md               # Progress tracker
```

## Testing

### Build verification:
```bash
npm run build
```

### Manual testing checklist:
- [ ] User registration with key generation
- [ ] User login and key retrieval
- [ ] Key exchange between two users
- [ ] TOFU validation (first exchange vs. key change)
- [ ] Send encrypted message
- [ ] Receive and decrypt message
- [ ] Upload encrypted file
- [ ] Download and decrypt file
- [ ] Nonce replay protection (duplicate rejected)
- [ ] Timestamp validation (old messages rejected)
- [ ] Sequence ordering (out-of-order rejected)
- [ ] Parallel exchange prevention

### Security testing:
- [ ] Verify private keys in IndexedDB (never sent to server)
- [ ] Verify no plaintext in MongoDB (only ciphertext)
- [ ] Verify unique IVs per message
- [ ] Verify nonce uniqueness enforcement
- [ ] Verify signature verification working
- [ ] Verify TOFU warning on key change

## Academic Compliance

This project adheres to strict academic integrity guidelines:

- ✅ Custom key exchange protocol design (not copied from textbooks)
- ✅ 70%+ cryptographic logic written by team
- ✅ No third-party E2EE libraries (Signal, Libsodium, OpenPGP.js forbidden)
- ✅ Web Crypto API only for primitives
- ✅ All attack demonstrations from actual system
- ✅ Equal git contributions from all team members

## Security Logging

All security events logged to MongoDB:
- Authentication attempts (success/failure)
- Key exchange operations (signature verification)
- Failed message decryptions
- Detected replay attacks (duplicate nonces)
- Expired timestamp rejections
- Sequence violations
- Invalid signature attempts
- Unauthorized access attempts
- Public key changes (TOFU validation)

## Known Limitations

- Session keys expire after 30 days (manual re-exchange required)
- No key rotation mechanism (planned for future)
- No message deletion/editing (immutable by design)
- Single device per user (no cross-device sync)
- No group messaging (only 1-on-1 conversations)

## Future Work

- [ ] Complete MITM attack demonstrations
- [ ] Complete replay attack demonstrations
- [ ] Threat modeling (STRIDE analysis)
- [ ] Performance optimizations (Web Workers)
- [ ] Rate limiting on authentication
- [ ] Two-factor authentication (TOTP)
- [ ] Perfect forward secrecy enhancements

## Recent Security Improvements (2025-12-03)

- ✅ **Bob's Confirmation Verification**: Responder now verifies Alice's confirmation HMAC tag before completing exchange
- ✅ **TOFU Pattern**: Trust-On-First-Use pattern prevents public key substitution attacks
- ✅ **Parallel Exchange Prevention**: Only one active key exchange allowed per user pair at a time

## License

Academic project - Information Security Course

## Contributors

[Team member names and contributions - see workdone.md]
