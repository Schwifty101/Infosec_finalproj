/**
 * ECDSA Signature Generation and Verification
 * Using P-256 curve with SHA-256 hash
 *
 * Signatures are used to authenticate key exchange messages,
 * preventing man-in-the-middle attacks.
 *
 * Security: Each message is signed with the sender's long-term ECDSA
 * identity key (from Phase 1), binding the ephemeral ECDH public key
 * to the sender's identity.
 */

import { arrayBufferToBase64, base64ToArrayBuffer, stringToArrayBuffer } from './utils';

/**
 * Create signature payload from components
 *
 * Concatenates message components into a single buffer for signing.
 * Uses "||" as delimiter (actually concatenation, delimiter is conceptual).
 *
 * @param components - Array of strings to concatenate
 * @returns ArrayBuffer - Ready to sign
 */
export function createSignaturePayload(components: string[]): ArrayBuffer {
  try {
    // Join components with delimiter
    const payloadString = components.join('||');

    // Convert to ArrayBuffer
    const payload = stringToArrayBuffer(payloadString);

    console.log('✅ Signature payload created:', payloadString.substring(0, 100) + '...');
    return payload;
  } catch (error) {
    console.error('❌ Failed to create signature payload:', error);
    throw new Error('Failed to create signature payload');
  }
}

/**
 * Sign data using ECDSA private key
 *
 * Generates an ECDSA signature over the provided data using P-256 curve.
 *
 * @param privateKey - ECDSA P-256 private key (CryptoKey)
 * @param data - Data to sign (ArrayBuffer)
 * @returns Promise<string> - Base64 encoded signature
 */
export async function signData(
  privateKey: CryptoKey,
  data: ArrayBuffer
): Promise<string> {
  try {
    console.log('🔐 Signing data with ECDSA private key...');

    // Verify key is correct type
    if (privateKey.type !== 'private') {
      throw new Error('Expected private key for signing');
    }

    // Sign with ECDSA
    const signature = await crypto.subtle.sign(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      privateKey,
      data
    );

    // Encode as Base64
    const signatureBase64 = arrayBufferToBase64(signature);

    console.log('✅ Data signed successfully');
    return signatureBase64;
  } catch (error) {
    console.error('❌ Signature generation failed:', error);
    throw new Error('Failed to sign data');
  }
}

/**
 * Verify ECDSA signature
 *
 * Verifies that the signature is valid for the given data and public key.
 *
 * @param publicKey - ECDSA P-256 public key (CryptoKey)
 * @param signatureBase64 - Base64 encoded signature
 * @param data - Original data that was signed
 * @returns Promise<boolean> - True if signature is valid
 */
export async function verifySignature(
  publicKey: CryptoKey,
  signatureBase64: string,
  data: ArrayBuffer
): Promise<boolean> {
  try {
    console.log('🔐 Verifying ECDSA signature...');

    // Verify key is correct type
    if (publicKey.type !== 'public') {
      throw new Error('Expected public key for verification');
    }

    // Decode signature
    const signature = base64ToArrayBuffer(signatureBase64);

    // Verify signature
    const isValid = await crypto.subtle.verify(
      {
        name: 'ECDSA',
        hash: 'SHA-256',
      },
      publicKey,
      signature,
      data
    );

    if (isValid) {
      console.log('✅ Signature verified successfully');
    } else {
      console.warn('⚠️ Signature verification failed');
    }

    return isValid;
  } catch (error) {
    console.error('❌ Signature verification error:', error);
    return false;
  }
}

/**
 * Import ECDSA public key from JWK format
 *
 * Imports a public key for signature verification.
 *
 * @param jwkString - JWK formatted public key (JSON string)
 * @returns Promise<CryptoKey> - ECDSA public key
 */
export async function importECDSAPublicKey(jwkString: string): Promise<CryptoKey> {
  try {
    // Parse JWK
    const jwk = JSON.parse(jwkString);

    // Validate JWK structure
    if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y) {
      throw new Error('Invalid JWK format for ECDSA public key');
    }

    // Import as ECDSA public key
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

    console.log('✅ ECDSA public key imported for verification');
    return publicKey;
  } catch (error) {
    console.error('❌ Failed to import ECDSA public key:', error);
    throw new Error('Failed to import ECDSA public key');
  }
}

/**
 * Import ECDSA private key from JWK format
 *
 * Imports a private key for signature generation.
 *
 * @param jwkString - JWK formatted private key (JSON string)
 * @returns Promise<CryptoKey> - ECDSA private key
 */
export async function importECDSAPrivateKey(jwkString: string): Promise<CryptoKey> {
  try {
    // Parse JWK
    const jwk = JSON.parse(jwkString);

    // Validate JWK structure (private key has 'd' parameter)
    if (!jwk.kty || !jwk.crv || !jwk.x || !jwk.y || !jwk.d) {
      throw new Error('Invalid JWK format for ECDSA private key');
    }

    // Import as ECDSA private key
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

    console.log('✅ ECDSA private key imported for signing');
    return privateKey;
  } catch (error) {
    console.error('❌ Failed to import ECDSA private key:', error);
    throw new Error('Failed to import ECDSA private key');
  }
}

/**
 * Sign key exchange init message
 *
 * Creates signature over init message components.
 * Payload: ephemPubKey || nonce || timestamp || responderUserId || initiatorUserId
 *
 * @param privateKey - Initiator's ECDSA private key
 * @param ephemeralPublicKeyJwk - Ephemeral ECDH public key (JWK string)
 * @param nonce - Nonce (Base64)
 * @param timestamp - Timestamp (number)
 * @param responderId - Responder user ID
 * @param initiatorId - Initiator user ID
 * @returns Promise<string> - Base64 signature
 */
export async function signInitMessage(
  privateKey: CryptoKey,
  ephemeralPublicKeyJwk: string,
  nonce: string,
  timestamp: number,
  responderId: string,
  initiatorId: string
): Promise<string> {
  const components = [
    ephemeralPublicKeyJwk,
    nonce,
    timestamp.toString(),
    responderId,
    initiatorId,
  ];

  const payload = createSignaturePayload(components);
  return await signData(privateKey, payload);
}

/**
 * Verify key exchange init message signature
 *
 * @param publicKey - Initiator's ECDSA public key
 * @param signature - Signature to verify (Base64)
 * @param ephemeralPublicKeyJwk - Ephemeral ECDH public key
 * @param nonce - Nonce
 * @param timestamp - Timestamp
 * @param responderId - Responder user ID
 * @param initiatorId - Initiator user ID
 * @returns Promise<boolean> - True if valid
 */
export async function verifyInitMessage(
  publicKey: CryptoKey,
  signature: string,
  ephemeralPublicKeyJwk: string,
  nonce: string,
  timestamp: number,
  responderId: string,
  initiatorId: string
): Promise<boolean> {
  const components = [
    ephemeralPublicKeyJwk,
    nonce,
    timestamp.toString(),
    responderId,
    initiatorId,
  ];

  const payload = createSignaturePayload(components);
  return await verifySignature(publicKey, signature, payload);
}

/**
 * Sign key exchange response message
 *
 * Payload: ephemPubKey || nonce || timestamp || initiatorUserId || responderUserId || initiatorNonce
 *
 * @param privateKey - Responder's ECDSA private key
 * @param ephemeralPublicKeyJwk - Responder's ephemeral ECDH public key
 * @param nonce - Responder's nonce
 * @param timestamp - Timestamp
 * @param initiatorId - Initiator user ID
 * @param responderId - Responder user ID
 * @param initiatorNonce - Initiator's nonce (for binding)
 * @returns Promise<string> - Base64 signature
 */
export async function signResponseMessage(
  privateKey: CryptoKey,
  ephemeralPublicKeyJwk: string,
  nonce: string,
  timestamp: number,
  initiatorId: string,
  responderId: string,
  initiatorNonce: string
): Promise<string> {
  const components = [
    ephemeralPublicKeyJwk,
    nonce,
    timestamp.toString(),
    initiatorId,
    responderId,
    initiatorNonce,
  ];

  const payload = createSignaturePayload(components);
  return await signData(privateKey, payload);
}

/**
 * Verify key exchange response message signature
 *
 * @param publicKey - Responder's ECDSA public key
 * @param signature - Signature to verify
 * @param ephemeralPublicKeyJwk - Responder's ephemeral public key
 * @param nonce - Responder's nonce
 * @param timestamp - Timestamp
 * @param initiatorId - Initiator user ID
 * @param responderId - Responder user ID
 * @param initiatorNonce - Initiator's nonce
 * @returns Promise<boolean> - True if valid
 */
export async function verifyResponseMessage(
  publicKey: CryptoKey,
  signature: string,
  ephemeralPublicKeyJwk: string,
  nonce: string,
  timestamp: number,
  initiatorId: string,
  responderId: string,
  initiatorNonce: string
): Promise<boolean> {
  const components = [
    ephemeralPublicKeyJwk,
    nonce,
    timestamp.toString(),
    initiatorId,
    responderId,
    initiatorNonce,
  ];

  const payload = createSignaturePayload(components);
  return await verifySignature(publicKey, signature, payload);
}
