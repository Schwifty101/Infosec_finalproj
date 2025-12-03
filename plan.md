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
  - **Code Reference**: `app/api/auth/register/route.ts:55-56`
    ```typescript
    // Password hashing with bcrypt (10 rounds, auto-salted)
    const passwordHash = await bcrypt.hash(password, 10);
    ```

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
  - **Code Reference**: `lib/crypto/keyGeneration.ts:20-38`
    ```typescript
    // Generate ECC P-256 key pair for ECDSA signatures
    export async function generateKeyPair(): Promise<CryptoKeyPair> {
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256', // NIST P-256 curve
        },
        true, // extractable
        ['sign', 'verify']
      );
      return keyPair;
    }
    ```

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
  - **Code Reference**: `lib/crypto/keyStorage.ts:68-100`
    ```typescript
    // Store private key in IndexedDB (client-side only)
    export async function storePrivateKey(userId: string, privateKeyJwk: string) {
      const db = await initDB();
      const transaction = db.transaction([STORE_NAME], 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const data = {
        userId,
        privateKey: privateKeyJwk,
        storedAt: new Date().toISOString(),
      };
      await store.put(data);
    }
    ```

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
  - **Code Reference**: `app/api/keys/route.ts` (POST), `app/api/keys/[userId]/route.ts` (GET)
    ```typescript
    // Store public key on server
    POST /api/keys
    Body: { userId, publicKey (JWK string) }

    // Retrieve public key
    GET /api/keys/:userId
    Returns: { publicKey (JWK string) }
    ```

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
  - **Code Reference**: `lib/crypto/protocol.ts`
    ```typescript
    // Protocol Flow:
    // 1. Initiator: Generate ephemeral ECDH key pair + sign with identity key
    // 2. Initiator → Responder: {ephemeralPublicKey, signature, nonce}
    // 3. Responder: Generate ephemeral ECDH key pair + verify signature
    // 4. Responder: Compute shared secret → derive session key (HKDF)
    // 5. Responder → Initiator: {ephemeralPublicKey, signature, nonce, keyConfirmation}
    // 6. Initiator: Verify signature + keyConfirmation
    // 7. Both: Session key established
    ```

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
  - **Code Reference**: `lib/crypto/keyExchange.ts:234-263`
    ```typescript
    // Derive session key from ECDH shared secret
    export async function deriveSessionKeyFromECDH(
      myPrivateKey: CryptoKey,
      peerPublicKey: CryptoKey,
      myNonce: string,
      peerNonce: string,
      userId1: string,
      userId2: string
    ): Promise<CryptoKey> {
      // Step 1: Compute ECDH shared secret
      const sharedSecret = await performECDH(myPrivateKey, peerPublicKey);

      // Step 2: Create salt from nonces
      const salt = await createSaltFromNonces(myNonce, peerNonce);

      // Step 3: Derive AES-256-GCM session key using HKDF
      const sessionKey = await deriveSessionKey(sharedSecret, salt, info);

      return sessionKey;
    }
    ```
  - **ECDH Computation**: `lib/crypto/keyExchange.ts:184-215`
    ```typescript
    // Compute shared secret
    const sharedSecret = await crypto.subtle.deriveBits(
      { name: 'ECDH', public: peerPublicKey },
      privateKey,
      256 // 256 bits for P-256
    );
    ```

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
  - **Code Reference**: `lib/crypto/sessionKeys.ts`
    ```typescript
    // Store session key in IndexedDB
    export async function storeSessionKey(
      conversationId: string,
      sessionKey: CryptoKey
    ) {
      const db = await initDB();
      const exportedKey = await crypto.subtle.exportKey('raw', sessionKey);
      const keyData = arrayBufferToBase64(exportedKey);

      await store.put({
        conversationId,
        keyData,
        createdAt: new Date().toISOString(),
      });
    }
    ```
  - **Conversation ID**: `lib/crypto/keyExchange.ts:275-279`
    ```typescript
    // Deterministic conversation ID (sorted user IDs)
    export function getConversationId(userId1: string, userId2: string): string {
      const sorted = [userId1, userId2].sort();
      return `${sorted[0]}_${sorted[1]}`;
    }
    ```

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
  - **Code Reference**: `lib/crypto/messaging-client.ts:47-120`
    ```typescript
    // Encrypt message with AES-256-GCM
    export async function encryptMessage(
      plaintext: string,
      sessionKey: CryptoKey,
      sequenceNumber: number
    ): Promise<EncryptedMessage> {
      const iv = generateIV(); // 12 bytes (fresh per message)
      const nonce = generateNonce(); // 16 bytes (replay protection)

      // AAD includes nonce + sequence number
      const aad = stringToArrayBuffer(JSON.stringify({ nonce, sequenceNumber }));

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        sessionKey,
        stringToArrayBuffer(plaintext)
      );

      // Output: ciphertext (separate) + authTag (last 16 bytes)
      return { ciphertext, iv, authTag, nonce, sequenceNumber };
    }
    ```

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
  - **Code Reference**: `lib/crypto/messaging-client.ts:134-216`
    ```typescript
    // Decrypt message with AES-256-GCM
    export async function decryptMessage(
      ciphertext: string,
      iv: string,
      authTag: string,
      nonce: string,
      sequenceNumber: number,
      sessionKey: CryptoKey
    ): Promise<string> {
      // Reconstruct AAD (must match encryption)
      const aad = stringToArrayBuffer(JSON.stringify({ nonce, sequenceNumber }));

      // Concatenate ciphertext + authTag (required by GCM)
      const combined = new Uint8Array(ciphertextBuffer.byteLength + authTagBuffer.byteLength);

      // Decrypt and verify authentication tag
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        sessionKey,
        combined.buffer
      );

      return arrayBufferToString(decrypted);
    }
    ```

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
  - **Code Reference**: `lib/db/models.ts`
    ```typescript
    // MongoDB Message Schema
    interface MessageDocument {
      conversationId: string;       // Deterministic ID (sorted user IDs)
      senderId: string;
      receiverId: string;
      ciphertext: string;           // Base64 encrypted content
      iv: string;                   // Base64 IV (12 bytes)
      authTag: string;              // Base64 authentication tag (16 bytes)
      nonce: string;                // Base64 nonce (replay protection)
      sequenceNumber: number;       // Per-conversation counter
      timestamp: Date;
      createdAt: Date;
    }
    ```

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
  - **Code Reference**: `app/components/ChatWindow.tsx`, `app/components/MessageList.tsx`
    ```typescript
    // Components:
    // - ChatWindow: Main chat interface with encryption status indicator
    // - MessageList: Displays decrypted messages with sender info
    // - MessageInput: Encrypts and sends messages
    // - MessageBubble: Individual message display with timestamp
    ```

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
  - **Code Reference**: `lib/crypto/fileEncryption.ts:46-126`
    ```typescript
    // Encrypt file with AES-256-GCM
    export async function encryptFile(
      fileData: ArrayBuffer,
      filename: string,
      mimeType: string,
      sessionKey: CryptoKey
    ): Promise<EncryptedFile> {
      const iv = generateIV(); // Fresh IV per file
      const nonce = generateNonce();

      // AAD includes nonce + filename + mimeType
      const aad = stringToArrayBuffer(JSON.stringify({ nonce, filename, mimeType }));

      const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        sessionKey,
        fileData
      );

      return { ciphertext, iv, authTag, nonce, filename, mimeType, size };
    }
    ```

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
  - **Code Reference**: `app/api/files/upload/route.ts`
    ```typescript
    // POST /api/files/upload
    // Body: { conversationId, ciphertext, iv, authTag, nonce, filename, mimeType, size }

    // MongoDB File Schema
    interface FileDocument {
      conversationId: string;
      senderId: string;
      receiverId: string;
      ciphertext: string;    // Base64 encrypted file
      iv: string;            // Base64 IV
      authTag: string;       // Base64 auth tag
      nonce: string;         // Base64 nonce
      filename: string;      // Original filename
      mimeType: string;
      size: number;          // Original file size
      uploadedAt: Date;
    }
    ```

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
  - **Code Reference**: `lib/crypto/fileEncryption.ts:141-206`
    ```typescript
    // Decrypt file with AES-256-GCM
    export async function decryptFile(
      ciphertext: string,
      iv: string,
      authTag: string,
      nonce: string,
      filename: string,
      mimeType: string,
      sessionKey: CryptoKey
    ): Promise<ArrayBuffer> {
      // Reconstruct AAD (must match encryption)
      const aad = stringToArrayBuffer(JSON.stringify({ nonce, filename, mimeType }));

      // Decrypt and verify authentication tag
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        sessionKey,
        combined.buffer
      );

      return decrypted; // ArrayBuffer ready for download
    }
    ```

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
  - **Code Reference**: `lib/crypto/utils.ts`
    ```typescript
    // Generate cryptographically secure nonce
    export function generateNonce(): string {
      const nonceArray = crypto.getRandomValues(new Uint8Array(16)); // 16 bytes
      return arrayBufferToBase64(nonceArray.buffer);
    }
    ```
  - **Server Validation**: `app/api/messages/send/route.ts`
    ```typescript
    // Check for duplicate nonce (24-hour TTL)
    const existingNonce = await noncesCollection.findOne({
      nonce,
      expiresAt: { $gt: new Date() }
    });

    if (existingNonce) {
      await logSecurityEvent('replay_attack_nonce', 'Duplicate nonce detected');
      return NextResponse.json({ success: false, message: 'Duplicate nonce' });
    }

    // Store nonce with 24-hour expiration
    await noncesCollection.insertOne({
      nonce,
      conversationId,
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000)
    });
    ```

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
  - **Code Reference**: `app/api/messages/send/route.ts`
    ```typescript
    // Validate timestamp (5-minute window)
    const messageTime = new Date(timestamp);
    const now = new Date();
    const timeDiff = Math.abs(now.getTime() - messageTime.getTime());
    const MAX_TIME_DIFF = 5 * 60 * 1000; // 5 minutes

    if (timeDiff > MAX_TIME_DIFF) {
      await logSecurityEvent(
        'replay_attack_timestamp',
        `Message timestamp outside valid window: ${timeDiff}ms difference`
      );
      return NextResponse.json({
        success: false,
        message: 'Invalid timestamp: message too old or from future'
      });
    }
    ```

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
  - **Code Reference**: `lib/crypto/messaging-client.ts:316-335`
    ```typescript
    // Get next sequence number from server
    export async function getNextSequenceNumber(
      conversationId: string,
      senderId: string
    ): Promise<number> {
      const response = await fetch(
        `/api/messages/sequence/${conversationId}?senderId=${senderId}`
      );
      const data = await response.json();
      return data.nextSequenceNumber || 1;
    }
    ```
  - **Server Validation**: `app/api/messages/send/route.ts`
    ```typescript
    // Validate sequence number (must be exactly expectedSeq)
    const expectedSeq = await getNextSequenceForSender(conversationId, senderId);

    if (sequenceNumber !== expectedSeq) {
      await logSecurityEvent(
        'sequence_violation',
        `Expected ${expectedSeq}, got ${sequenceNumber}`
      );
      return NextResponse.json({
        success: false,
        message: `Invalid sequence number. Expected ${expectedSeq}`
      });
    }
    ```

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
  - **Code Reference**: `app/attack-demos/replay/page.tsx`
    ```typescript
    // Replay attack demo page
    // 1. Capture message from network (Wireshark/Browser DevTools)
    // 2. Extract: ciphertext, iv, authTag, nonce, timestamp, sequenceNumber
    // 3. Replay exact same data to /api/messages/send
    // 4. Server rejects due to:
    //    - Duplicate nonce (already seen)
    //    - Old timestamp (outside 5-min window)
    //    - Invalid sequence (already used)
    // 5. Check security logs for replay attack detection
    ```

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
  - **Code Reference**: `app/attack-demos/mitm-vulnerable/page.tsx`
    ```typescript
    // Vulnerable key exchange (NO signatures)
    // 1. Alice → Server: ephemeralPublicKeyA (no signature)
    // 2. Server forwards to Bob
    // 3. Attacker intercepts, replaces with attackerPublicKey
    // 4. Bob computes shared secret with ATTACKER's key
    // 5. Attacker can decrypt all messages between Alice & Bob
    //
    // Demonstration:
    // - Use BurpSuite to intercept HTTP requests
    // - Replace public key in transit
    // - Show successful MITM attack
    ```

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
  - **Code Reference**: `app/attack-demos/mitm-protected/page.tsx`
    ```typescript
    // Protected key exchange (WITH signatures)
    // 1. Alice → Server: { ephemeralPublicKeyA, signatureA, nonce }
    //    - signatureA = Sign(ephemeralPublicKeyA + nonce, aliceIdentityPrivateKey)
    // 2. Server forwards to Bob
    // 3. Attacker intercepts, tries to replace public key
    // 4. Bob verifies signature using Alice's identity public key
    // 5. Signature verification FAILS (attacker doesn't have Alice's private key)
    // 6. Bob rejects key exchange, alerts user
    //
    // Demonstration with signatures from lib/crypto/signatures.ts
    ```
  - **Signature Functions**: `lib/crypto/signatures.ts`
    ```typescript
    // Sign data with ECDSA private key
    export async function signData(data: string, privateKey: CryptoKey): Promise<string> {
      const dataBuffer = stringToArrayBuffer(data);
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        privateKey,
        dataBuffer
      );
      return arrayBufferToBase64(signature);
    }

    // Verify signature with ECDSA public key
    export async function verifySignature(
      data: string,
      signature: string,
      publicKey: CryptoKey
    ): Promise<boolean> {
      const dataBuffer = stringToArrayBuffer(data);
      const signatureBuffer = base64ToArrayBuffer(signature);
      return await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKey,
        signatureBuffer,
        dataBuffer
      );
    }
    ```

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
  - **Code Reference**: `app/api/auth/login/route.ts`
    ```typescript
    // Log authentication attempt
    await db.collection(Collections.LOGS).insertOne({
      type: 'auth',
      userId: user._id.toString(),
      details: success ? `Login successful: ${username}` : `Login failed: ${username}`,
      timestamp: new Date(),
      ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
      userAgent: request.headers.get('user-agent') || 'unknown',
      success: success,
    });
    ```

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
  - **Code Reference**: `app/api/key-exchange/initiate/route.ts`, `app/api/key-exchange/respond/route.ts`
    ```typescript
    // Log key exchange initiation
    await db.collection(Collections.LOGS).insertOne({
      type: 'key_exchange',
      userId: initiatorId,
      details: `Key exchange initiated with ${responderId}`,
      timestamp: new Date(),
      success: true,
      metadata: {
        sessionId: sessionId,
        phase: 'initiate',
      }
    });

    // Log signature verification
    await db.collection(Collections.LOGS).insertOne({
      type: 'signature_verification',
      details: signatureValid ? 'Valid signature' : 'Invalid signature',
      success: signatureValid,
      timestamp: new Date(),
    });
    ```

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
  - **Code Reference**: `lib/crypto/messaging-client.ts:197-209`
    ```typescript
    // Log decryption failure (client-side → server)
    catch (error: any) {
      await fetch('/api/security/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'decrypt_fail',
          details: `Message decryption failed. Error: ${error.message}`,
          conversationId: conversationId,
          timestamp: new Date().toISOString(),
        }),
      });

      throw new Error('Authentication failed: Message tampered or incorrect key');
    }
    ```

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
  - **Code Reference**: `app/api/security/log/route.ts:12-59`
    ```typescript
    // Security logging API
    export async function POST(request: NextRequest) {
      const { type, messageId, details, userId, conversationId } = await request.json();

      await logsCollection.insertOne({
        type: type,                    // 'replay_attack_nonce', 'replay_attack_timestamp', etc.
        messageId: messageId || null,
        userId: userId || null,
        conversationId: conversationId || null,
        details: details,
        timestamp: new Date(),
        ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
        userAgent: request.headers.get('user-agent') || 'unknown',
        success: false,
      });
    }
    ```

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
  - **Code Reference**: `app/logs/page.tsx`
    ```typescript
    // Security logs viewer
    // Features:
    // - Filter by type: auth, key_exchange, decrypt_fail, replay_attack, etc.
    // - Search by userId, conversationId, date range
    // - Sort by timestamp (newest first)
    // - Export to CSV for report submission
    // - Real-time log updates (refresh button)
    // - Color-coded by success/failure
    ```
  - **Logs API**: `app/api/logs/route.ts`
    ```typescript
    // GET /api/logs?type=auth&userId=123&startDate=...&endDate=...
    // Returns filtered logs from MongoDB
    ```

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
  - **Documentation Reference**: `docs/threat-model/STRIDE_ANALYSIS.md`
    ```markdown
    # STRIDE Analysis

    ## Spoofing
    - T1: Attacker impersonates user (Mitigated: bcrypt password hashing)
    - T2: MITM in key exchange (Mitigated: Digital signatures)

    ## Tampering
    - T3: Message modification (Mitigated: AES-GCM authentication tags)
    - T4: Replay attacks (Mitigated: Nonce + timestamp + sequence)

    ## Repudiation
    - T5: User denies sending message (Mitigated: Digital signatures, logs)

    ## Information Disclosure
    - T6: Plaintext exposure (Mitigated: E2EE with AES-256-GCM)
    - T7: Private key leakage (Mitigated: IndexedDB client-side only)

    ## Denial of Service
    - T8: Resource exhaustion (Partial: Need rate limiting)

    ## Elevation of Privilege
    - T9: Access to other users' messages (Mitigated: Conversation-based access)
    ```

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
  - **Documentation Reference**: `docs/threat-model/THREAT_DEFENSE_MAPPING.md`
    ```markdown
    # Threat-Defense Mapping

    | Threat ID | Threat | Defense Mechanism | Implementation |
    |-----------|--------|-------------------|----------------|
    | T1 | User impersonation | Bcrypt password hashing | app/api/auth/register/route.ts:56 |
    | T2 | MITM attack | ECDSA signatures in key exchange | lib/crypto/signatures.ts |
    | T3 | Message tampering | AES-GCM auth tags | lib/crypto/messaging-client.ts:85 |
    | T4 | Replay attacks | Nonce + timestamp + sequence | app/api/messages/send/route.ts |
    | T6 | Plaintext exposure | AES-256-GCM E2EE | lib/crypto/messaging-client.ts:47 |
    | T7 | Private key leakage | IndexedDB client-only | lib/crypto/keyStorage.ts:68 |
    ```

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
  - **Documentation Reference**: `docs/threat-model/VULNERABILITIES.md`
    ```markdown
    # Known Vulnerabilities & Limitations

    ## V1: No Rate Limiting (HIGH)
    - Issue: No protection against brute-force login attempts
    - Impact: Attacker could attempt password guessing
    - Mitigation: Add rate limiting to /api/auth/login

    ## V2: No Perfect Forward Secrecy (MEDIUM)
    - Issue: If long-term keys compromised, past sessions at risk
    - Current: Using ephemeral ECDH (good), but no automatic rotation
    - Improvement: Implement automatic session key rotation

    ## V3: Browser-Based Key Storage (MEDIUM)
    - Issue: IndexedDB accessible to XSS attacks
    - Current: Best browser-based option available
    - Improvement: Consider WebAuthn for key protection

    ## V4: No Multi-Device Support (LOW)
    - Issue: Keys tied to single browser
    - Improvement: Implement secure key backup/sync mechanism
    ```

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
  - **Documentation Reference**: `docs/architecture/SYSTEM_ARCHITECTURE.md`
    ```markdown
    # System Architecture

    ## Client-Side Components
    - UI Layer: React/Next.js components (app/components/)
    - Crypto Layer: Web Crypto API operations (lib/crypto/)
    - Storage Layer: IndexedDB (lib/crypto/keyStorage.ts)

    ## Server-Side Components
    - API Layer: Next.js API routes (app/api/)
    - Database: MongoDB (lib/db/models.ts)
    - Auth: bcrypt password validation

    ## Data Flow
    Client → Encrypt → Network → Server → MongoDB (encrypted)
    Server → MongoDB → Network → Client → Decrypt → Display
    ```

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
  - **Documentation Reference**: `docs/architecture/PROTOCOL_FLOWS.md`
    ```markdown
    # Key Exchange Protocol Flow

    ## Phase 1: Initiation
    Initiator:
    1. Generate ephemeral ECDH key pair (lib/crypto/keyExchange.ts:25)
    2. Create nonce (16 bytes)
    3. Sign: signature = Sign(ephemeralPublicKey + nonce, identityPrivateKey)
    4. Send: { ephemeralPublicKey, signature, nonce, initiatorId }

    ## Phase 2: Response
    Responder:
    1. Verify signature using initiator's identity public key
    2. Generate own ephemeral ECDH key pair
    3. Compute shared secret via ECDH
    4. Derive session key via HKDF
    5. Create key confirmation = HMAC(sessionKey, "confirmation")
    6. Send: { ephemeralPublicKey, signature, nonce, keyConfirmation }

    ## Phase 3: Finalization
    Initiator:
    1. Verify responder's signature
    2. Compute shared secret via ECDH
    3. Derive session key via HKDF
    4. Verify key confirmation matches
    5. Store session key in IndexedDB
    ```

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
  - **Documentation Reference**: `docs/architecture/PROTOCOL_FLOWS.md`
    ```markdown
    # Message Encryption Flow

    1. Get session key from IndexedDB (conversationId)
    2. Get next sequence number from server
    3. Generate IV (12 bytes) + nonce (16 bytes)
    4. Create AAD = { nonce, sequenceNumber }
    5. Encrypt: AES-256-GCM(plaintext, sessionKey, IV, AAD)
    6. Send to server: { ciphertext, iv, authTag, nonce, sequenceNumber, timestamp }
    7. Server validates: nonce (unique), timestamp (5-min), sequence (expected)
    8. Server stores encrypted message in MongoDB

    # Message Decryption Flow

    1. Fetch encrypted message from server
    2. Get session key from IndexedDB (conversationId)
    3. Reconstruct AAD = { nonce, sequenceNumber }
    4. Decrypt: AES-256-GCM(ciphertext + authTag, sessionKey, IV, AAD)
    5. If auth tag invalid → throw error, log to security logs
    6. Display plaintext in UI
    ```

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
  - **Code Reference**: `lib/db/models.ts`
    ```typescript
    // Users Collection
    interface UserDocument {
      username: string;           // Unique, indexed
      passwordHash: string;       // bcrypt hash
      publicKey?: string;         // ECDSA P-256 public key (JWK)
      createdAt: Date;
    }

    // Messages Collection
    interface MessageDocument {
      conversationId: string;     // Indexed
      senderId: string;
      receiverId: string;
      ciphertext: string;         // Base64 encrypted
      iv: string;                 // Base64
      authTag: string;            // Base64
      nonce: string;              // Base64, for replay protection
      sequenceNumber: number;
      timestamp: Date;
      createdAt: Date;
    }

    // Nonces Collection (TTL index)
    interface NonceDocument {
      nonce: string;              // Indexed
      conversationId: string;
      expiresAt: Date;            // TTL index (24 hours)
    }

    // Logs Collection
    interface LogDocument {
      type: string;               // 'auth', 'key_exchange', 'decrypt_fail', etc.
      userId?: string;
      messageId?: string;
      conversationId?: string;
      details: string;
      timestamp: Date;
      ipAddress: string;
      userAgent?: string;
      success: boolean;
    }
    ```

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
  - **Documentation Reference**: `docs/DEPLOYMENT_GUIDE.md`
    ```markdown
    # Deployment Guide

    ## Prerequisites
    - Node.js 18+ and npm
    - MongoDB 5.0+ (local or Atlas)

    ## Installation Steps
    1. Clone repository
    2. Install dependencies: `npm install`
    3. Configure environment variables:
       - MONGODB_URI=mongodb://localhost:27017/secure-messaging
       - NEXTAUTH_SECRET=your-secret-here
    4. Start development server: `npm run dev`
    5. Access at http://localhost:3000

    ## Production Deployment
    1. Build: `npm run build`
    2. Start: `npm start`
    3. Deploy to Vercel/Railway with MongoDB Atlas

    ## Security Considerations
    - Always use HTTPS in production
    - Set secure environment variables
    - Enable CORS restrictions
    - Configure CSP headers
    ```

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

## 6. Code References & Implementation

### 6.1 User Authentication

**Registration API**: `app/api/auth/register/route.ts:55-56`
```typescript
// Password hashing with bcrypt (10 rounds)
const passwordHash = await bcrypt.hash(password, 10);
```

**Login API**: `app/api/auth/login/route.ts`
- Username validation & user lookup
- Password verification with bcrypt.compare()
- Authentication logging

### 6.2 Key Generation & Storage

**Key Generation**: `lib/crypto/keyGeneration.ts:20-38`
```typescript
// Generate ECC P-256 key pair for signing
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'ECDSA',
    namedCurve: 'P-256',
  },
  true,
  ['sign', 'verify']
);
```

**ECDH Key Pair**: `lib/crypto/keyGeneration.ts:46-63` - For key exchange

**Key Storage**: `lib/crypto/keyStorage.ts:68-100`
```typescript
// Store private key in IndexedDB
export async function storePrivateKey(userId: string, privateKeyJwk: string) {
  const db = await initDB();
  const transaction = db.transaction([STORE_NAME], 'readwrite');
  const store = transaction.objectStore(STORE_NAME);
  const data = { userId, privateKey: privateKeyJwk, storedAt: new Date().toISOString() };
  const request = store.put(data);
}
```

**Key Retrieval**: `lib/crypto/keyStorage.ts:108-136`

### 6.3 Key Exchange Protocol

**Ephemeral Key Generation**: `lib/crypto/keyExchange.ts:25-45`
```typescript
// Generate ephemeral ECDH P-256 key pair
const keyPair = await crypto.subtle.generateKey(
  { name: 'ECDH', namedCurve: 'P-256' },
  true,
  ['deriveKey', 'deriveBits']
);
```

**ECDH Computation**: `lib/crypto/keyExchange.ts:184-215`
```typescript
// Compute shared secret using private key + peer's public key
const sharedSecret = await crypto.subtle.deriveBits(
  { name: 'ECDH', public: peerPublicKey },
  privateKey,
  256
);
```

**Session Key Derivation**: `lib/crypto/keyExchange.ts:234-263`
- ECDH shared secret → HKDF → AES-256-GCM session key
- Uses nonces as salt + user IDs as info

**Protocol Flow**: `lib/crypto/protocol.ts`
- `initiateKeyExchange()` - Initiator sends ephemeral public key + signature + nonce
- `respondToKeyExchange()` - Responder sends ephemeral public key + signature + nonce + key confirmation
- `finalizeKeyExchange()` - Initiator verifies confirmation and stores session key

### 6.4 Message Encryption

**Encryption**: `lib/crypto/messaging-client.ts:47-120`
```typescript
// Encrypt message with AES-256-GCM
const iv = generateIV(); // 12 bytes
const nonce = generateNonce(); // 16 bytes
const aad = stringToArrayBuffer(JSON.stringify({ nonce, sequenceNumber }));

const encrypted = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
  sessionKey,
  plaintextBuffer
);
```

**Decryption**: `lib/crypto/messaging-client.ts:134-216`
```typescript
// Decrypt with AAD verification
const decrypted = await crypto.subtle.decrypt(
  { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
  sessionKey,
  combined // ciphertext + authTag
);
```

**Sequence Number Validation**: `lib/crypto/messaging-client.ts:225-241`

**Send Message API**: `app/api/messages/send/route.ts`
- Nonce validation (duplicate detection)
- Timestamp verification (5-minute window)
- Sequence number validation
- Replay attack logging

### 6.5 File Encryption

**File Encryption**: `lib/crypto/fileEncryption.ts:46-126`
```typescript
// Encrypt file with AES-256-GCM
const iv = generateIV();
const nonce = generateNonce();
const aad = stringToArrayBuffer(JSON.stringify({ nonce, filename, mimeType }));

const encrypted = await crypto.subtle.encrypt(
  { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
  sessionKey,
  fileData
);
```

**File Decryption**: `lib/crypto/fileEncryption.ts:141-206`
- AAD includes nonce + filename + mimeType
- Authentication tag verification

**Upload API**: `app/api/files/upload/route.ts`
- Stores encrypted file data in MongoDB
- 50MB size limit with chunking support

**Download API**: `app/api/files/download/[fileId]/route.ts`

### 6.6 Replay Attack Protection

**Nonce Generation**: `lib/crypto/utils.ts`
```typescript
export function generateNonce(): string {
  const nonceArray = crypto.getRandomValues(new Uint8Array(16));
  return arrayBufferToBase64(nonceArray.buffer);
}
```

**Server-Side Validation**: `app/api/messages/send/route.ts`
```typescript
// Check for duplicate nonce (24-hour TTL)
const existingNonce = await noncesCollection.findOne({ nonce, expiresAt: { $gt: new Date() } });
if (existingNonce) {
  await logSecurityEvent('replay_attack_nonce', 'Duplicate nonce detected');
  return NextResponse.json({ success: false, message: 'Duplicate nonce detected' });
}

// Validate timestamp (5-minute window)
const messageTime = new Date(timestamp);
const now = new Date();
const timeDiff = Math.abs(now.getTime() - messageTime.getTime());
if (timeDiff > 5 * 60 * 1000) {
  await logSecurityEvent('replay_attack_timestamp', 'Message timestamp outside valid window');
  return NextResponse.json({ success: false, message: 'Invalid timestamp' });
}
```

### 6.7 Security Logging

**Client-Side Logging API**: `app/api/security/log/route.ts:12-59`
```typescript
// Log security events (decryption failures, attacks)
await logsCollection.insertOne({
  type: type,
  messageId: messageId || null,
  userId: userId || null,
  conversationId: conversationId || null,
  details: details,
  timestamp: timestamp ? new Date(timestamp) : new Date(),
  ipAddress: request.headers.get('x-forwarded-for') || 'unknown',
  userAgent: request.headers.get('user-agent') || 'unknown',
  success: false,
});
```

**Logs Viewing Interface**: `app/logs/page.tsx`
- Filter by type, user, date range
- Export to CSV
- Real-time security monitoring

### 6.8 Database Models

**MongoDB Collections**: `lib/db/models.ts`
- `users`: Username, passwordHash, publicKey, createdAt
- `messages`: Encrypted ciphertext, IV, authTag, nonce, sequenceNumber, sender/receiver IDs
- `files`: Encrypted data, IV, authTag, nonce, filename, mimeType, size
- `nonces`: Nonce tracking with TTL index for replay protection
- `logs`: Security events, authentication attempts, attack detection

---

## References

See `DEVELOPMENTRULES.md` for complete project requirements and constraints.
See `workdone.md` for tracking completed work and progress.
