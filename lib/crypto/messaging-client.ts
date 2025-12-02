/**
 * Message Encryption/Decryption - CLIENT-SIDE ONLY
 *
 * Provides end-to-end encryption for messages using AES-256-GCM
 * with session keys established in Phase 2
 *
 * This file contains ONLY client-side cryptographic functions
 * with NO server/MongoDB dependencies
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
  sessionKey: CryptoKey,
  conversationId?: string
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
      combined.buffer as ArrayBuffer
    );

    // Convert to string
    const plaintext = arrayBufferToString(decrypted);

    console.log('✅ Message decrypted successfully', {
      plaintextLength: plaintext.length,
      sequenceNumber,
    });

    return plaintext;
  } catch (error: any) {
    console.error('❌ Message decryption failed:', error);

    // Log decryption failure to server
    try {
      await fetch('/api/security/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'decrypt_fail',
          details: `Message decryption failed. Error: ${error.message}`,
          conversationId: conversationId,
        }),
      });
    } catch (logError) {
      console.error('Failed to log decryption error:', logError);
    }

    // GCM authentication failure means message was tampered or wrong key
    throw new Error(
      'Authentication failed: Message tampered or incorrect session key'
    );
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

/**
 * Get next sequence number for client-side
 * For client-side, we query the server API
 *
 * @param conversationId - Deterministic conversation ID
 * @returns Promise<number> - Next sequence number to use
 */
export async function getNextSequenceNumber(
  conversationId: string
): Promise<number> {
  try {
    const response = await fetch(`/api/messages/sequence/${conversationId}`);

    if (!response.ok) {
      console.error('Failed to fetch sequence number from server');
      return 1;
    }

    const data = await response.json();
    return data.nextSequenceNumber || 1;
  } catch (error) {
    console.error('Failed to get sequence number:', error);
    // Default to 1 if error
    return 1;
  }
}
