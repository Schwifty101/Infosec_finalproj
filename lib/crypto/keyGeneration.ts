/**
 * Client-Side Cryptographic Key Generation
 * Uses Web Crypto API for ECC P-256 key pair generation
 *
 * CRITICAL: This code runs ONLY on the client-side
 * Private keys NEVER leave the browser
 */

/**
 * Generate ECC P-256 key pair for signing and key agreement
 *
 * @returns Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }>
 *
 * Algorithm: ECDSA with P-256 curve
 * - P-256 (secp256r1) is NIST-approved
 * - Better performance than RSA-2048
 * - 256-bit ECC ≈ 3072-bit RSA security level
 * - Widely supported by Web Crypto API
 */
export async function generateKeyPair(): Promise<CryptoKeyPair> {
  try {
    // Generate ECC P-256 key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // NIST P-256 curve
      },
      true, // extractable (needed to export/store keys)
      ['sign', 'verify'] // key usages
    );

    console.log('✅ ECC P-256 key pair generated successfully');
    return keyPair;
  } catch (error) {
    console.error('❌ Key generation failed:', error);
    throw new Error('Failed to generate cryptographic key pair');
  }
}

/**
 * Generate ECC P-256 key pair for ECDH key agreement
 * Used for deriving shared secrets with other users
 *
 * @returns Promise<{ publicKey: CryptoKey, privateKey: CryptoKey }>
 */
export async function generateECDHKeyPair(): Promise<CryptoKeyPair> {
  try {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true, // extractable
      ['deriveKey', 'deriveBits'] // key usages for key agreement
    );

    console.log('✅ ECDH P-256 key pair generated successfully');
    return keyPair;
  } catch (error) {
    console.error('❌ ECDH key generation failed:', error);
    throw new Error('Failed to generate ECDH key pair');
  }
}

/**
 * Export public key to JWK format for transmission to server
 *
 * @param publicKey - CryptoKey object
 * @returns Promise<string> - JSON string of JWK
 */
export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);
    return JSON.stringify(jwk);
  } catch (error) {
    console.error('❌ Public key export failed:', error);
    throw new Error('Failed to export public key');
  }
}

/**
 * Export private key to JWK format for storage
 *
 * WARNING: Private keys should only be exported for secure storage
 * NEVER transmit private keys over the network
 *
 * @param privateKey - CryptoKey object
 * @returns Promise<string> - JSON string of JWK
 */
export async function exportPrivateKey(privateKey: CryptoKey): Promise<string> {
  try {
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    return JSON.stringify(jwk);
  } catch (error) {
    console.error('❌ Private key export failed:', error);
    throw new Error('Failed to export private key');
  }
}

/**
 * Import public key from JWK format
 *
 * @param jwkString - JSON string of JWK
 * @returns Promise<CryptoKey>
 */
export async function importPublicKey(jwkString: string): Promise<CryptoKey> {
  try {
    const jwk = JSON.parse(jwkString);
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['verify']
    );
    return publicKey;
  } catch (error) {
    console.error('❌ Public key import failed:', error);
    throw new Error('Failed to import public key');
  }
}

/**
 * Import private key from JWK format
 *
 * @param jwkString - JSON string of JWK
 * @returns Promise<CryptoKey>
 */
export async function importPrivateKey(jwkString: string): Promise<CryptoKey> {
  try {
    const jwk = JSON.parse(jwkString);
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      true,
      ['sign']
    );
    return privateKey;
  } catch (error) {
    console.error('❌ Private key import failed:', error);
    throw new Error('Failed to import private key');
  }
}
