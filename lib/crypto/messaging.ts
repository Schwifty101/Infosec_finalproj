/**
 * Message Encryption/Decryption for Phase 3
 *
 * Provides end-to-end encryption for messages using AES-256-GCM
 * with session keys established in Phase 2
 *
 * Security Features:
 * - AES-256-GCM for authenticated encryption
 * - Per-message nonces for replay protection
 * - Sequence numbers to prevent reordering attacks
 * - Additional Authenticated Data (AAD) includes nonce + sequence number
 */

import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  stringToArrayBuffer,
  arrayBufferToString,
  generateIV,
  generateNonce,
} from './utils';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';

/**
 * Encrypted message structure
 * All fields are Base64 encoded for transport
 */
export interface EncryptedMessage {
  ciphertext: string;      // Base64 encrypted content
  iv: string;              // Base64 IV (12 bytes for GCM)
  authTag: string;         // Base64 authentication tag (16 bytes)
  nonce: string;           // Base64 nonce (16 bytes, replay protection)
  sequenceNumber: number;  // Per-conversation counter
}

/**
 * Encrypt plaintext message with AES-256-GCM
 *
 * @param plaintext - Message text to encrypt
 * @param sessionKey - AES-256-GCM session key from Phase 2
 * @param sequenceNumber - Current sequence number for conversation
 * @returns Promise<EncryptedMessage> - Encrypted message with metadata
 * @throws Error if encryption fails or session key is invalid
 */
export async function encryptMessage(
  plaintext: string,
  sessionKey: CryptoKey,
  sequenceNumber: number
): Promise<EncryptedMessage> {
  try {
    // Validate session key algorithm
    if (sessionKey.algorithm.name !== 'AES-GCM') {
      throw new Error('Session key must be AES-GCM');
    }

    // Validate input
    if (!plaintext || plaintext.trim().length === 0) {
      throw new Error('Message cannot be empty');
    }

    if (sequenceNumber < 0) {
      throw new Error('Sequence number must be non-negative');
    }

    // Generate unique IV (12 bytes for GCM)
    const iv = generateIV();

    // Generate nonce for replay protection (16 bytes)
    const nonce = generateNonce();

    // Create Additional Authenticated Data (AAD)
    // Includes nonce and sequence number to prevent replay/reorder attacks
    const aadObject = {
      nonce,
      sequenceNumber,
    };
    const aad = stringToArrayBuffer(JSON.stringify(aadObject));

    // Convert plaintext to ArrayBuffer
    const plaintextBuffer = stringToArrayBuffer(plaintext);

    // Encrypt with AES-256-GCM
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv as Uint8Array<ArrayBuffer>,
        additionalData: aad,
        tagLength: 128, // 16 bytes auth tag
      },
      sessionKey,
      plaintextBuffer
    );

    // GCM output = ciphertext + authTag (last 16 bytes)
    const encryptedArray = new Uint8Array(encrypted);
    const ciphertextArray = encryptedArray.slice(0, -16);
    const authTagArray = encryptedArray.slice(-16);

    // Convert to Base64 for transport
    const result: EncryptedMessage = {
      ciphertext: arrayBufferToBase64(ciphertextArray.buffer as ArrayBuffer),
      iv: arrayBufferToBase64(iv.buffer as ArrayBuffer),
      authTag: arrayBufferToBase64(authTagArray.buffer as ArrayBuffer),
      nonce,
      sequenceNumber,
    };

    console.log('✅ Message encrypted successfully', {
      ciphertextLength: result.ciphertext.length,
      sequenceNumber: result.sequenceNumber,
    });

    return result;
  } catch (error) {
    console.error('❌ Message encryption failed:', error);
    throw new Error('Failed to encrypt message');
  }
}

/**
 * Decrypt ciphertext message with AES-256-GCM
 *
 * @param ciphertext - Base64 encrypted message
 * @param iv - Base64 initialization vector
 * @param authTag - Base64 authentication tag
 * @param nonce - Base64 nonce
 * @param sequenceNumber - Message sequence number
 * @param sessionKey - AES-256-GCM session key
 * @returns Promise<string> - Decrypted plaintext message
 * @throws Error if decryption fails or authentication fails
 */
export async function decryptMessage(
  ciphertext: string,
  iv: string,
  authTag: string,
  nonce: string,
  sequenceNumber: number,
  sessionKey: CryptoKey
): Promise<string> {
  try {
    // Validate session key algorithm
    if (sessionKey.algorithm.name !== 'AES-GCM') {
      throw new Error('Session key must be AES-GCM');
    }

    // Decode Base64 inputs
    const ivBuffer = base64ToArrayBuffer(iv);
    const ciphertextBuffer = base64ToArrayBuffer(ciphertext);
    const authTagBuffer = base64ToArrayBuffer(authTag);

    // Concatenate ciphertext + authTag (required by GCM)
    const combined = new Uint8Array(
      ciphertextBuffer.byteLength + authTagBuffer.byteLength
    );
    combined.set(new Uint8Array(ciphertextBuffer), 0);
    combined.set(
      new Uint8Array(authTagBuffer),
      ciphertextBuffer.byteLength
    );

    // Recreate AAD (must match encryption AAD exactly)
    const aadObject = {
      nonce,
      sequenceNumber,
    };
    const aad = stringToArrayBuffer(JSON.stringify(aadObject));

    // Decrypt with AES-256-GCM
    // If authentication fails, this will throw an error
    const decrypted = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBuffer,
        additionalData: aad,
        tagLength: 128,
      },
      sessionKey,
      combined.buffer
    );

    // Convert to string
    const plaintext = arrayBufferToString(decrypted);

    console.log('✅ Message decrypted successfully', {
      plaintextLength: plaintext.length,
      sequenceNumber,
    });

    return plaintext;
  } catch (error) {
    console.error('❌ Message decryption failed:', error);
    // GCM authentication failure means message was tampered or wrong key
    throw new Error(
      'Authentication failed: Message tampered or incorrect session key'
    );
  }
}

/**
 * Get next sequence number for a conversation
 * Retrieves from MongoDB or starts at 1
 *
 * @param conversationId - Deterministic conversation ID
 * @returns Promise<number> - Next sequence number to use
 */
export async function getNextSequenceNumber(
  conversationId: string
): Promise<number> {
  try {
    // For client-side: Store in IndexedDB alongside session key
    // For simplicity, query MongoDB for max sequenceNumber + 1
    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    // Parse conversationId to get user IDs
    const [userId1, userId2] = conversationId.split('_').sort();

    // Find latest message in conversation
    const latestMessage = await messagesCollection
      .findOne(
        {
          $or: [
            { senderId: userId1, receiverId: userId2 },
            { senderId: userId2, receiverId: userId1 },
          ],
        },
        { sort: { sequenceNumber: -1 } }
      );

    if (!latestMessage || latestMessage.sequenceNumber === undefined) {
      // First message in conversation
      return 1;
    }

    return latestMessage.sequenceNumber + 1;
  } catch (error) {
    console.error('Failed to get sequence number:', error);
    // Default to 1 if error
    return 1;
  }
}

/**
 * Validate sequence number to prevent replay/reorder attacks
 *
 * @param receivedSeq - Sequence number from incoming message
 * @param expectedSeq - Expected next sequence number
 * @returns boolean - True if sequence number is valid
 */
export function validateSequenceNumber(
  receivedSeq: number,
  expectedSeq: number
): boolean {
  // Allow only sequential messages (no gaps, no duplicates)
  const isValid = receivedSeq === expectedSeq;

  if (!isValid) {
    console.warn('⚠️ Invalid sequence number detected', {
      received: receivedSeq,
      expected: expectedSeq,
      difference: receivedSeq - expectedSeq,
    });
  }

  return isValid;
}

/**
 * Get last sequence number for a conversation
 * Used for validation on server-side
 *
 * @param conversationId - Deterministic conversation ID
 * @param senderId - Sender's user ID
 * @returns Promise<number> - Last sequence number from this sender
 */
export async function getLastSequenceNumber(
  conversationId: string,
  senderId: string
): Promise<number> {
  try {
    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    const [userId1, userId2] = conversationId.split('_').sort();

    // Find latest message from this sender in this conversation
    const latestMessage = await messagesCollection
      .findOne(
        {
          senderId,
          $or: [
            { senderId: userId1, receiverId: userId2 },
            { senderId: userId2, receiverId: userId1 },
          ],
        },
        { sort: { sequenceNumber: -1 } }
      );

    if (!latestMessage || latestMessage.sequenceNumber === undefined) {
      return 0; // No messages yet
    }

    return latestMessage.sequenceNumber;
  } catch (error) {
    console.error('Failed to get last sequence number:', error);
    return 0;
  }
}

/**
 * Check if nonce has been used before (replay protection)
 * Server-side only - checks MongoDB nonces collection
 *
 * @param nonce - Base64 nonce to check
 * @returns Promise<boolean> - True if nonce has been used
 */
export async function isNonceUsed(nonce: string): Promise<boolean> {
  try {
    const db = await getDatabase();
    const noncesCollection = db.collection(Collections.NONCES);

    const existingNonce = await noncesCollection.findOne({ nonce });

    return existingNonce !== null;
  } catch (error) {
    console.error('Failed to check nonce:', error);
    return false; // Fail open (assume not used)
  }
}

/**
 * Store nonce to prevent replay attacks
 * Server-side only - stores in MongoDB with TTL
 *
 * @param nonce - Base64 nonce
 * @param userId - User ID who generated the nonce
 * @param messageId - Associated message ID
 * @returns Promise<void>
 */
export async function storeNonce(
  nonce: string,
  userId: string,
  messageId: string
): Promise<void> {
  try {
    const db = await getDatabase();
    const noncesCollection = db.collection(Collections.NONCES);

    await noncesCollection.insertOne({
      nonce,
      userId,
      messageId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours TTL
    });

    console.log('✅ Nonce stored for replay protection');
  } catch (error) {
    console.error('Failed to store nonce:', error);
    // Non-fatal - continue processing
  }
}

/**
 * Create HMAC for message confirmation (optional)
 * Can be used for additional confirmation layers
 *
 * @param sessionKey - Session key
 * @param data - Data to sign
 * @returns Promise<string> - Base64 HMAC
 */
export async function createMessageHMAC(
  sessionKey: CryptoKey,
  data: string
): Promise<string> {
  const dataBuffer = stringToArrayBuffer(data);

  // Import session key as HMAC key
  const hmacKey = await crypto.subtle.importKey(
    'raw',
    await crypto.subtle.exportKey('raw', sessionKey),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', hmacKey, dataBuffer);

  return arrayBufferToBase64(signature);
}

/**
 * Verify message HMAC
 *
 * @param sessionKey - Session key
 * @param data - Original data
 * @param hmac - Base64 HMAC to verify
 * @returns Promise<boolean> - True if HMAC is valid
 */
export async function verifyMessageHMAC(
  sessionKey: CryptoKey,
  data: string,
  hmac: string
): Promise<boolean> {
  try {
    const dataBuffer = stringToArrayBuffer(data);
    const hmacBuffer = base64ToArrayBuffer(hmac);

    const hmacKey = await crypto.subtle.importKey(
      'raw',
      await crypto.subtle.exportKey('raw', sessionKey),
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      false,
      ['verify']
    );

    return await crypto.subtle.verify('HMAC', hmacKey, hmacBuffer, dataBuffer);
  } catch (error) {
    console.error('HMAC verification failed:', error);
    return false;
  }
}
