/**
 * File Encryption/Decryption for Phase 4
 *
 * Provides end-to-end encryption for files using AES-256-GCM
 * with session keys established in Phase 2
 *
 * Security Features:
 * - AES-256-GCM for authenticated encryption
 * - Per-file nonces for replay protection
 * - Additional Authenticated Data (AAD) includes nonce + filename + mimeType
 * - Fresh IV per file (never reused)
 */

import {
  arrayBufferToBase64,
  base64ToArrayBuffer,
  stringToArrayBuffer,
  generateIV,
  generateNonce,
} from './utils';

/**
 * Encrypted file structure
 * All fields are Base64 encoded for transport/storage
 */
export interface EncryptedFile {
  ciphertext: string;      // Base64 encrypted file data
  iv: string;              // Base64 IV (12 bytes for GCM)
  authTag: string;         // Base64 authentication tag (16 bytes)
  nonce: string;           // Base64 nonce (16 bytes, replay protection)
  filename: string;        // Original filename
  mimeType: string;        // File MIME type
  size: number;            // Original file size in bytes
}

/**
 * Encrypt file with AES-256-GCM
 *
 * @param fileData - File as ArrayBuffer
 * @param filename - Original filename
 * @param mimeType - File MIME type
 * @param sessionKey - AES-256-GCM session key from Phase 2
 * @returns Promise<EncryptedFile> - Encrypted file with metadata
 * @throws Error if encryption fails or session key is invalid
 */
export async function encryptFile(
  fileData: ArrayBuffer,
  filename: string,
  mimeType: string,
  sessionKey: CryptoKey
): Promise<EncryptedFile> {
  try {
    // Validate session key algorithm
    if (sessionKey.algorithm.name !== 'AES-GCM') {
      throw new Error('Session key must be AES-GCM');
    }

    // Validate input
    if (!fileData || fileData.byteLength === 0) {
      throw new Error('File data cannot be empty');
    }

    if (!filename || filename.trim().length === 0) {
      throw new Error('Filename cannot be empty');
    }

    if (!mimeType || mimeType.trim().length === 0) {
      throw new Error('MIME type cannot be empty');
    }

    // Generate unique IV (12 bytes for GCM)
    const iv = generateIV();

    // Generate nonce for replay protection (16 bytes)
    const nonce = generateNonce();

    // Create Additional Authenticated Data (AAD)
    // Includes nonce, filename, and mimeType to prevent tampering
    const aadObject = {
      nonce,
      filename,
      mimeType,
    };
    const aad = stringToArrayBuffer(JSON.stringify(aadObject));

    // Encrypt with AES-256-GCM
    const encrypted = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        additionalData: aad,
        tagLength: 128, // 16 bytes auth tag
      },
      sessionKey,
      fileData
    );

    // GCM output = ciphertext + authTag (last 16 bytes)
    const encryptedArray = new Uint8Array(encrypted);
    const ciphertextArray = encryptedArray.slice(0, -16);
    const authTagArray = encryptedArray.slice(-16);

    // Convert to Base64 for transport
    const result: EncryptedFile = {
      ciphertext: arrayBufferToBase64(ciphertextArray.buffer),
      iv: arrayBufferToBase64(iv.buffer),
      authTag: arrayBufferToBase64(authTagArray.buffer),
      nonce,
      filename,
      mimeType,
      size: fileData.byteLength,
    };

    console.log('✅ File encrypted successfully', {
      filename,
      mimeType,
      originalSize: fileData.byteLength,
      ciphertextLength: result.ciphertext.length,
    });

    return result;
  } catch (error) {
    console.error('❌ File encryption failed:', error);
    throw new Error('Failed to encrypt file');
  }
}

/**
 * Decrypt file with AES-256-GCM
 *
 * @param ciphertext - Base64 encrypted file
 * @param iv - Base64 initialization vector
 * @param authTag - Base64 authentication tag
 * @param nonce - Base64 nonce
 * @param filename - Original filename (for AAD reconstruction)
 * @param mimeType - File MIME type (for AAD reconstruction)
 * @param sessionKey - AES-256-GCM session key
 * @returns Promise<ArrayBuffer> - Decrypted file data
 * @throws Error if decryption fails or authentication fails
 */
export async function decryptFile(
  ciphertext: string,
  iv: string,
  authTag: string,
  nonce: string,
  filename: string,
  mimeType: string,
  sessionKey: CryptoKey
): Promise<ArrayBuffer> {
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
      filename,
      mimeType,
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

    console.log('✅ File decrypted successfully', {
      filename,
      mimeType,
      decryptedSize: decrypted.byteLength,
    });

    return decrypted;
  } catch (error) {
    console.error('❌ File decryption failed:', error);
    // GCM authentication failure means file was tampered or wrong key
    throw new Error(
      'Authentication failed: File tampered or incorrect session key'
    );
  }
}
