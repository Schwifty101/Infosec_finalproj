/**
 * ECDH Key Exchange Operations
 * Using P-256 curve for ephemeral key agreement
 *
 * This module handles:
 * - Ephemeral ECDH key pair generation
 * - ECDH shared secret computation
 * - Session key derivation using HKDF
 * - Key import/export operations
 *
 * Security: Ephemeral keys provide forward secrecy. Even if long-term
 * identity keys are compromised, past session keys remain secure.
 */

import { deriveSessionKey, createSaltFromNonces, createHkdfInfo } from './hkdf';

/**
 * Generate ephemeral ECDH P-256 key pair
 *
 * Creates a new key pair for one key exchange session.
 * These keys should be deleted after the session key is derived.
 *
 * @returns Promise<CryptoKeyPair> - Ephemeral ECDH key pair
 */
export async function generateEphemeralKeyPair(): Promise<CryptoKeyPair> {
  try {
    console.log('🔐 Generating ephemeral ECDH P-256 key pair...');

    // Generate ECDH P-256 key pair
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true, // extractable (needed for export and deriveBits)
      ['deriveKey', 'deriveBits']
    );

    console.log('✅ Ephemeral ECDH key pair generated');
    return keyPair;
  } catch (error) {
    console.error('❌ Ephemeral key generation failed:', error);
    throw new Error('Failed to generate ephemeral key pair');
  }
}

/**
 * Export ECDH public key to JWK format
 *
 * @param publicKey - ECDH public key (CryptoKey)
 * @returns Promise<string> - JSON string of JWK
 */
export async function exportECDHPublicKey(publicKey: CryptoKey): Promise<string> {
  try {
    if (publicKey.type !== 'public') {
      throw new Error('Expected public key for export');
    }

    // Export as JWK
    const jwk = await crypto.subtle.exportKey('jwk', publicKey);

    // Convert to JSON string
    const jwkString = JSON.stringify(jwk);

    console.log('✅ ECDH public key exported to JWK');
    return jwkString;
  } catch (error) {
    console.error('❌ ECDH public key export failed:', error);
    throw new Error('Failed to export ECDH public key');
  }
}

/**
 * Export ECDH private key to JWK format
 *
 * WARNING: Private keys should only be exported for temporary storage
 * during key exchange. Delete after session key is derived.
 *
 * @param privateKey - ECDH private key (CryptoKey)
 * @returns Promise<string> - JSON string of JWK
 */
export async function exportECDHPrivateKey(privateKey: CryptoKey): Promise<string> {
  try {
    if (privateKey.type !== 'private') {
      throw new Error('Expected private key for export');
    }

    // Export as JWK
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);

    // Convert to JSON string
    const jwkString = JSON.stringify(jwk);

    console.log('✅ ECDH private key exported to JWK');
    return jwkString;
  } catch (error) {
    console.error('❌ ECDH private key export failed:', error);
    throw new Error('Failed to export ECDH private key');
  }
}

/**
 * Import ECDH public key from JWK format
 *
 * @param jwkString - JWK formatted public key (JSON string)
 * @returns Promise<CryptoKey> - ECDH public key
 */
export async function importECDHPublicKey(jwkString: string): Promise<CryptoKey> {
  try {
    // Parse JWK
    const jwk = JSON.parse(jwkString);

    // Validate JWK structure
    if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y) {
      throw new Error('Invalid JWK format for ECDH public key');
    }

    // Import as ECDH public key
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      [] // No usages for public key (used in deriveBits)
    );

    console.log('✅ ECDH public key imported');
    return publicKey;
  } catch (error) {
    console.error('❌ Failed to import ECDH public key:', error);
    throw new Error('Failed to import ECDH public key');
  }
}

/**
 * Import ECDH private key from JWK format
 *
 * @param jwkString - JWK formatted private key (JSON string)
 * @returns Promise<CryptoKey> - ECDH private key
 */
export async function importECDHPrivateKey(jwkString: string): Promise<CryptoKey> {
  try {
    // Parse JWK
    const jwk = JSON.parse(jwkString);

    // Validate JWK structure (private key has 'd' parameter)
    if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y || !jwk.d) {
      throw new Error('Invalid JWK format for ECDH private key');
    }

    // Import as ECDH private key
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );

    console.log('✅ ECDH private key imported');
    return privateKey;
  } catch (error) {
    console.error('❌ Failed to import ECDH private key:', error);
    throw new Error('Failed to import ECDH private key');
  }
}

/**
 * Perform ECDH to compute shared secret
 *
 * Computes the shared secret using your private key and peer's public key.
 * Both parties will compute the same shared secret.
 *
 * @param privateKey - Your ECDH private key
 * @param peerPublicKey - Peer's ECDH public key
 * @returns Promise<ArrayBuffer> - Shared secret (raw bits)
 */
export async function performECDH(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<ArrayBuffer> {
  try {
    console.log('🔐 Performing ECDH to compute shared secret...');

    // Verify key types
    if (privateKey.type !== 'private') {
      throw new Error('Expected private key for ECDH');
    }
    if (peerPublicKey.type !== 'public') {
      throw new Error('Expected public key for ECDH');
    }

    // Derive bits (shared secret)
    const sharedSecret = await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: peerPublicKey,
      },
      privateKey,
      256 // 256 bits for P-256
    );

    console.log('✅ ECDH shared secret computed');
    return sharedSecret;
  } catch (error) {
    console.error('❌ ECDH computation failed:', error);
    throw new Error('Failed to compute ECDH shared secret');
  }
}

/**
 * Derive AES-256-GCM session key from ECDH shared secret
 *
 * Complete process:
 * 1. Compute ECDH shared secret
 * 2. Create salt from both nonces
 * 3. Create info string with user IDs
 * 4. Use HKDF to derive session key
 *
 * @param myPrivateKey - Your ephemeral ECDH private key
 * @param peerPublicKey - Peer's ephemeral ECDH public key
 * @param myNonce - Your nonce (Base64)
 * @param peerNonce - Peer's nonce (Base64)
 * @param userId1 - First user ID (initiator)
 * @param userId2 - Second user ID (responder)
 * @returns Promise<CryptoKey> - AES-256-GCM session key
 */
export async function deriveSessionKeyFromECDH(
  myPrivateKey: CryptoKey,
  peerPublicKey: CryptoKey,
  myNonce: string,
  peerNonce: string,
  userId1: string,
  userId2: string
): Promise<CryptoKey> {
  try {
    console.log('🔐 Deriving session key from ECDH...');

    // Step 1: Compute ECDH shared secret
    const sharedSecret = await performECDH(myPrivateKey, peerPublicKey);

    // Step 2: Create salt from nonces
    const salt = await createSaltFromNonces(myNonce, peerNonce);

    // Step 3: Create info string with user IDs
    const info = createHkdfInfo(userId1, userId2);

    // Step 4: Derive session key using HKDF
    const sessionKey = await deriveSessionKey(sharedSecret, salt, info);

    console.log('✅ Session key derived from ECDH successfully');
    return sessionKey;
  } catch (error) {
    console.error('❌ Session key derivation failed:', error);
    throw new Error('Failed to derive session key from ECDH');
  }
}

/**
 * Get deterministic conversation ID for two users
 *
 * Creates a consistent ID regardless of who initiates the conversation.
 * Used for session key storage and retrieval.
 *
 * @param userId1 - First user ID
 * @param userId2 - Second user ID
 * @returns string - Deterministic conversation ID (format: "userId1_userId2")
 */
export function getConversationId(userId1: string, userId2: string): string {
  // Sort IDs alphabetically for consistency
  const sorted = [userId1, userId2].sort();
  return `${sorted[0]}_${sorted[1]}`;
}

/**
 * Verify that both parties can derive the same shared secret
 *
 * Test helper function to verify ECDH works correctly.
 * Generates two key pairs and verifies they produce the same shared secret.
 *
 * @returns Promise<boolean> - True if shared secrets match
 */
export async function testECDHAgreement(): Promise<boolean> {
  try {
    console.log('🧪 Testing ECDH agreement...');

    // Alice generates key pair
    const aliceKeyPair = await generateEphemeralKeyPair();

    // Bob generates key pair
    const bobKeyPair = await generateEphemeralKeyPair();

    // Alice computes shared secret
    const aliceSharedSecret = await performECDH(
      aliceKeyPair.privateKey,
      bobKeyPair.publicKey
    );

    // Bob computes shared secret
    const bobSharedSecret = await performECDH(
      bobKeyPair.privateKey,
      aliceKeyPair.publicKey
    );

    // Compare shared secrets
    const aliceBytes = new Uint8Array(aliceSharedSecret);
    const bobBytes = new Uint8Array(bobSharedSecret);

    if (aliceBytes.length !== bobBytes.length) {
      console.error('❌ Shared secrets have different lengths');
      return false;
    }

    for (let i = 0; i < aliceBytes.length; i++) {
      if (aliceBytes[i] !== bobBytes[i]) {
        console.error('❌ Shared secrets do not match');
        return false;
      }
    }

    console.log('✅ ECDH agreement test passed: shared secrets match!');
    return true;
  } catch (error) {
    console.error('❌ ECDH agreement test failed:', error);
    return false;
  }
}
