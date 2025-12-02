/**
 * Cryptographic utility functions
 * Helper functions for encoding, decoding, and format conversions
 */

/**
 * Convert ArrayBuffer to Base64 string
 *
 * @param buffer - ArrayBuffer to convert
 * @returns string - Base64 encoded string
 */
export function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 *
 * @param base64 - Base64 encoded string
 * @returns ArrayBuffer
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert string to ArrayBuffer (UTF-8 encoding)
 *
 * @param str - String to convert
 * @returns ArrayBuffer
 */
export function stringToArrayBuffer(str: string): ArrayBuffer {
  const encoder = new TextEncoder();
  return encoder.encode(str).buffer;
}

/**
 * Convert ArrayBuffer to string (UTF-8 decoding)
 *
 * @param buffer - ArrayBuffer to convert
 * @returns string
 */
export function arrayBufferToString(buffer: ArrayBuffer): string {
  const decoder = new TextDecoder('utf-8');
  return decoder.decode(buffer);
}

/**
 * Generate cryptographically secure random bytes
 *
 * @param length - Number of bytes to generate
 * @returns Uint8Array
 */
export function generateRandomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Generate random IV (Initialization Vector) for AES-GCM
 * AES-GCM requires 12-byte (96-bit) IV
 *
 * @returns Uint8Array - 12-byte random IV
 */
export function generateIV(): Uint8Array {
  return generateRandomBytes(12);
}

/**
 * Generate random nonce for replay protection
 *
 * @returns string - Base64 encoded nonce
 */
export function generateNonce(): string {
  const nonce = generateRandomBytes(16);
  return arrayBufferToBase64(nonce.buffer as ArrayBuffer);
}

/**
 * Verify that a value is a valid timestamp within acceptable window
 *
 * @param timestamp - Timestamp to verify (milliseconds since epoch)
 * @param windowMs - Acceptable time window in milliseconds (default: 5 minutes)
 * @returns boolean - True if timestamp is within window
 */
export function verifyTimestamp(
  timestamp: number,
  windowMs: number = 5 * 60 * 1000
): boolean {
  const now = Date.now();
  const diff = Math.abs(now - timestamp);
  return diff <= windowMs;
}

/**
 * Create a SHA-256 hash of data
 *
 * @param data - ArrayBuffer to hash
 * @returns Promise<ArrayBuffer> - SHA-256 hash
 */
export async function sha256(data: ArrayBuffer): Promise<ArrayBuffer> {
  return await crypto.subtle.digest('SHA-256', data);
}

/**
 * Create a SHA-256 hash of string
 *
 * @param str - String to hash
 * @returns Promise<string> - Base64 encoded hash
 */
export async function sha256String(str: string): Promise<string> {
  const buffer = stringToArrayBuffer(str);
  const hash = await sha256(buffer);
  return arrayBufferToBase64(hash);
}

/**
 * Constant-time string comparison to prevent timing attacks
 *
 * @param a - First string
 * @param b - Second string
 * @returns boolean - True if strings are equal
 */
export function constantTimeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}
