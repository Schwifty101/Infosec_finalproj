/**
 * HKDF (HMAC-based Key Derivation Function) - RFC 5869
 * Using SHA-256 as the hash function
 *
 * HKDF is used to derive cryptographically strong session keys from
 * the ECDH shared secret. It consists of two phases:
 * 1. Extract: Derive a pseudorandom key (PRK) from the input keying material
 * 2. Expand: Expand the PRK into the desired length output keying material (OKM)
 *
 * Security: HKDF provides key separation, domain separation, and ensures
 * derived keys are indistinguishable from random even if the input has low entropy.
 */

import { arrayBufferToBase64, base64ToArrayBuffer, stringToArrayBuffer } from './utils';

/**
 * HKDF-Extract: Extract a pseudorandom key from input keying material
 *
 * PRK = HMAC-SHA256(salt, IKM)
 *
 * @param salt - Optional salt value (if null, uses zeros)
 * @param ikm - Input Keying Material (e.g., ECDH shared secret)
 * @returns Promise<ArrayBuffer> - Pseudorandom Key (PRK)
 */
export async function hkdfExtract(
  salt: ArrayBuffer | null,
  ikm: ArrayBuffer
): Promise<ArrayBuffer> {
  try {
    // If no salt provided, use array of zeros
    const actualSalt = salt || new ArrayBuffer(32); // 32 bytes of zeros for SHA-256

    // Import salt as HMAC key
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      actualSalt,
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );

    // PRK = HMAC-SHA256(salt, IKM)
    const prk = await crypto.subtle.sign('HMAC', hmacKey, ikm);

    console.log('✅ HKDF-Extract: PRK derived');
    return prk;
  } catch (error) {
    console.error('❌ HKDF-Extract failed:', error);
    throw new Error('HKDF-Extract failed');
  }
}

/**
 * HKDF-Expand: Expand PRK into desired length output keying material
 *
 * OKM = T(1) || T(2) || ... || T(N)
 * where:
 *   T(0) = empty string
 *   T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)
 *   N = ceil(length / HashLen)
 *
 * @param prk - Pseudorandom Key from Extract phase
 * @param info - Optional context/application-specific info string
 * @param length - Desired output length in bytes (max 8160 bytes for SHA-256)
 * @returns Promise<ArrayBuffer> - Output Keying Material (OKM)
 */
export async function hkdfExpand(
  prk: ArrayBuffer,
  info: string,
  length: number
): Promise<ArrayBuffer> {
  try {
    const hashLen = 32; // SHA-256 produces 32 bytes
    const maxLength = 255 * hashLen; // 8160 bytes

    if (length > maxLength) {
      throw new Error(`HKDF length too large: ${length} > ${maxLength}`);
    }

    // Import PRK as HMAC key
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      prk,
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );

    // Convert info string to ArrayBuffer
    const infoBuffer = stringToArrayBuffer(info);

    // Number of iterations needed
    const n = Math.ceil(length / hashLen);

    // Build OKM iteratively
    let t = new Uint8Array(0); // T(0) = empty
    let okm = new Uint8Array(0);

    for (let i = 1; i <= n; i++) {
      // Concatenate: T(i-1) || info || i
      const data = new Uint8Array(t.length + infoBuffer.byteLength + 1);
      data.set(t, 0);
      data.set(new Uint8Array(infoBuffer), t.length);
      data[t.length + infoBuffer.byteLength] = i;

      // T(i) = HMAC-SHA256(PRK, data)
      t = new Uint8Array(await crypto.subtle.sign('HMAC', hmacKey, data));

      // Append T(i) to OKM
      const newOkm = new Uint8Array(okm.length + t.length);
      newOkm.set(okm, 0);
      newOkm.set(t, okm.length);
      okm = newOkm;
    }

    // Return first 'length' bytes
    const result = okm.slice(0, length).buffer;
    console.log('✅ HKDF-Expand: OKM derived');
    return result;
  } catch (error) {
    console.error('❌ HKDF-Expand failed:', error);
    throw new Error('HKDF-Expand failed');
  }
}

/**
 * Complete HKDF: Extract then Expand
 *
 * Derives a cryptographically strong key from input keying material
 *
 * @param ikm - Input Keying Material (e.g., ECDH shared secret)
 * @param salt - Salt value for Extract phase
 * @param info - Context/application-specific info for Expand phase
 * @param keyLength - Desired key length in bytes (typically 32 for AES-256)
 * @returns Promise<ArrayBuffer> - Derived key material
 */
export async function hkdf(
  ikm: ArrayBuffer,
  salt: ArrayBuffer | null,
  info: string,
  keyLength: number
): Promise<ArrayBuffer> {
  try {
    console.log('🔐 Starting HKDF key derivation...');

    // Phase 1: Extract
    const prk = await hkdfExtract(salt, ikm);

    // Phase 2: Expand
    const okm = await hkdfExpand(prk, info, keyLength);

    console.log('✅ HKDF complete: Derived', keyLength, 'bytes');
    return okm;
  } catch (error) {
    console.error('❌ HKDF failed:', error);
    throw new Error('HKDF key derivation failed');
  }
}

/**
 * Derive an AES-256-GCM session key using HKDF
 *
 * Specifically for deriving session keys from ECDH shared secrets.
 * Returns a CryptoKey that can be used directly with AES-GCM encryption.
 *
 * @param sharedSecret - ECDH shared secret (ArrayBuffer)
 * @param salt - Salt for key derivation (typically hash of nonces)
 * @param info - Info string including user IDs for domain separation
 * @returns Promise<CryptoKey> - AES-256-GCM CryptoKey
 */
export async function deriveSessionKey(
  sharedSecret: ArrayBuffer,
  salt: ArrayBuffer | null,
  info: string
): Promise<CryptoKey> {
  try {
    console.log('🔐 Deriving AES-256-GCM session key...');

    // Derive 32 bytes (256 bits) for AES-256
    const keyMaterial = await hkdf(sharedSecret, salt, info, 32);

    // Import as AES-GCM key
    const sessionKey = await crypto.subtle.importKey(
      'raw',
      keyMaterial,
      {
        name: 'AES-GCM',
        length: 256,
      },
      true, // extractable (needed for IndexedDB storage)
      ['encrypt', 'decrypt']
    );

    console.log('✅ Session key derived successfully');
    return sessionKey;
  } catch (error) {
    console.error('❌ Session key derivation failed:', error);
    throw new Error('Failed to derive session key');
  }
}

/**
 * Create salt for HKDF from two nonces
 *
 * Combines two nonces using SHA-256 to create a salt for HKDF.
 * This binds the derived key to both nonces, ensuring freshness.
 *
 * @param nonceA - First nonce (Base64)
 * @param nonceB - Second nonce (Base64)
 * @returns Promise<ArrayBuffer> - SHA-256 hash to use as salt
 */
export async function createSaltFromNonces(
  nonceA: string,
  nonceB: string
): Promise<ArrayBuffer> {
  try {
    // Decode nonces
    const nonceABuffer = base64ToArrayBuffer(nonceA);
    const nonceBBuffer = base64ToArrayBuffer(nonceB);

    // Concatenate nonces
    const combined = new Uint8Array(nonceABuffer.byteLength + nonceBBuffer.byteLength);
    combined.set(new Uint8Array(nonceABuffer), 0);
    combined.set(new Uint8Array(nonceBBuffer), nonceABuffer.byteLength);

    // Hash with SHA-256
    const salt = await crypto.subtle.digest('SHA-256', combined);

    console.log('✅ Salt created from nonces');
    return salt;
  } catch (error) {
    console.error('❌ Salt creation failed:', error);
    throw new Error('Failed to create salt from nonces');
  }
}

/**
 * Create info string for HKDF
 *
 * Info string provides domain separation and binds the derived key
 * to the specific users involved in the key exchange.
 *
 * CRITICAL: User IDs are sorted alphabetically to ensure both parties
 * derive the same session key regardless of who initiates.
 *
 * @param userId1 - First user ID
 * @param userId2 - Second user ID
 * @returns string - Info string for HKDF
 */
export function createHkdfInfo(userId1: string, userId2: string): string {
  // Sort user IDs alphabetically for consistency
  const sorted = [userId1, userId2].sort();
  
  // Include protocol identifier and sorted user IDs
  // This ensures keys are bound to specific user pairs
  return `AECDH-ECDSA-SESSION-KEY||${sorted[0]}||${sorted[1]}`;
}
