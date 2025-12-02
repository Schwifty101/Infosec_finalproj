/**
 * AECDH-ECDSA Key Exchange Protocol Implementation
 *
 * Orchestrates the complete 3-message authenticated key exchange:
 * 1. Initiation (Alice → Bob): Ephemeral public key + signature
 * 2. Response (Bob → Alice): Ephemeral public key + signature + shared secret derived
 * 3. Confirmation (Alice → Bob): HMAC tag proving mutual key agreement
 *
 * Security Properties:
 * - Mutual authentication via ECDSA signatures
 * - Forward secrecy via ephemeral ECDH keys
 * - Replay protection via nonces and timestamps
 * - MITM protection via signed ephemeral keys
 */

import type {
  KeyExchangeInitMessage,
  KeyExchangeResponseMessage,
  KeyExchangeConfirmMessage,
} from '@/types/keyExchange';
import { KEY_EXCHANGE_CONFIG } from '@/types/keyExchange';
import { generateNonce, verifyTimestamp, sha256String, arrayBufferToBase64, stringToArrayBuffer } from './utils';
import { getPrivateKey } from './keyStorage';
import {
  storeSessionKey,
  storeEphemeralKey,
  getEphemeralKey,
  deleteEphemeralKey,
  getSessionMetadata,
} from './sessionKeys';
import {
  generateEphemeralKeyPair,
  exportECDHPublicKey,
  importECDHPublicKey,
  deriveSessionKeyFromECDH,
  getConversationId as getConversationIdUtil,
} from './keyExchange';
import {
  importECDSAPrivateKey,
  signInitMessage,
  verifyInitMessage,
  signResponseMessage,
  verifyResponseMessage,
  importECDSAPublicKey,
} from './signatures';

/**
 * Generate UUID v4 for session ID
 */
function generateSessionId(): string {
  return crypto.randomUUID();
}

/**
 * Verify timestamp is within acceptable window
 */
function isTimestampValid(timestamp: number): boolean {
  return verifyTimestamp(timestamp, KEY_EXCHANGE_CONFIG.TIMESTAMP_WINDOW_MS);
}

/**
 * Compute HMAC-SHA256 confirmation tag
 */
async function computeConfirmationTag(
  sessionKey: CryptoKey,
  initiatorId: string,
  responderId: string,
  nonceA: string,
  nonceB: string,
  timestamp: number
): Promise<string> {
  try {
    // Create payload for HMAC
    const payload = `${KEY_EXCHANGE_CONFIG.CONFIRMATION_PREFIX}||${initiatorId}||${responderId}||${nonceA}||${nonceB}||${timestamp}`;
    const payloadBuffer = stringToArrayBuffer(payload);

    // Export session key for HMAC
    const keyBytes = await crypto.subtle.exportKey('raw', sessionKey);

    // Import as HMAC key
    const hmacKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      {
        name: 'HMAC',
        hash: 'SHA-256',
      },
      false,
      ['sign']
    );

    // Compute HMAC
    const tag = await crypto.subtle.sign('HMAC', hmacKey, payloadBuffer);

    return arrayBufferToBase64(tag);
  } catch (error) {
    console.error('❌ Failed to compute confirmation tag:', error);
    throw new Error('Failed to compute confirmation tag');
  }
}

/**
 * Get conversation ID (deterministic)
 */
export function getConversationId(userId1: string, userId2: string): string {
  return getConversationIdUtil(userId1, userId2);
}

/**
 * Initiate key exchange (Alice/Initiator side)
 *
 * Creates MESSAGE 1: KeyExchangeInit
 *
 * @param myUserId - Initiator's user ID
 * @param peerUserId - Responder's user ID
 * @returns Promise<KeyExchangeInitMessage> - Init message to send to server
 */
export async function initiateKeyExchange(
  myUserId: string,
  peerUserId: string
): Promise<KeyExchangeInitMessage> {
  try {
    console.log('🔐 Initiating key exchange with user:', peerUserId);

    // Step 1: Generate ephemeral ECDH key pair
    const ephemeralKeyPair = await generateEphemeralKeyPair();

    // Step 2: Export ephemeral public key
    const ephemeralPublicKeyJwk = await exportECDHPublicKey(ephemeralKeyPair.publicKey);

    // Step 3: Generate nonce and timestamp
    const nonce = generateNonce();
    const timestamp = Date.now();

    // Step 4: Generate session ID
    const sessionId = generateSessionId();

    // Step 5: Store ephemeral private key temporarily (needed for response handling)
    await storeEphemeralKey(sessionId, ephemeralKeyPair.privateKey);

    // Step 6: Get my ECDSA private key for signing
    const myPrivateKeyJwk = await getPrivateKey(myUserId);
    if (!myPrivateKeyJwk) {
      throw new Error('Private key not found. Please register again.');
    }
    const myECDSAPrivateKey = await importECDSAPrivateKey(myPrivateKeyJwk);

    // Step 7: Sign the init message
    const signature = await signInitMessage(
      myECDSAPrivateKey,
      ephemeralPublicKeyJwk,
      nonce,
      timestamp,
      peerUserId,
      myUserId
    );

    // Step 8: Construct init message
    const initMessage: KeyExchangeInitMessage = {
      messageType: 'KEY_EXCHANGE_INIT',
      sessionId,
      initiatorId: myUserId,
      responderId: peerUserId,
      ephemeralPublicKey: ephemeralPublicKeyJwk,
      nonce,
      timestamp,
      signature,
    };

    console.log('✅ Key exchange initiation message created');
    return initMessage;
  } catch (error) {
    console.error('❌ Key exchange initiation failed:', error);
    throw error;
  }
}

/**
 * Handle key exchange initiation (Bob/Responder side)
 *
 * Processes MESSAGE 1 and creates MESSAGE 2: KeyExchangeResponse
 *
 * @param initMessage - Received init message
 * @param myUserId - Responder's user ID
 * @param initiatorPublicKeyJwk - Initiator's ECDSA public key (from server)
 * @returns Promise<KeyExchangeResponseMessage> - Response message to send back
 */
export async function handleKeyExchangeInit(
  initMessage: KeyExchangeInitMessage,
  myUserId: string,
  initiatorPublicKeyJwk: string
): Promise<KeyExchangeResponseMessage> {
  try {
    console.log('🔐 Handling key exchange init from:', initMessage.initiatorId);

    // Step 1: Verify timestamp
    if (!isTimestampValid(initMessage.timestamp)) {
      throw new Error('Init message timestamp expired or invalid');
    }

    // Step 2: Verify signature
    const initiatorPublicKey = await importECDSAPublicKey(initiatorPublicKeyJwk);
    const signatureValid = await verifyInitMessage(
      initiatorPublicKey,
      initMessage.signature,
      initMessage.ephemeralPublicKey,
      initMessage.nonce,
      initMessage.timestamp,
      initMessage.responderId,
      initMessage.initiatorId
    );

    if (!signatureValid) {
      throw new Error('Invalid signature on init message');
    }

    console.log('✅ Init message signature verified');

    // Step 3: Generate my ephemeral ECDH key pair
    const myEphemeralKeyPair = await generateEphemeralKeyPair();
    const myEphemeralPublicKeyJwk = await exportECDHPublicKey(myEphemeralKeyPair.publicKey);

    // Step 4: Import initiator's ephemeral public key
    const initiatorEphemeralPublicKey = await importECDHPublicKey(initMessage.ephemeralPublicKey);

    // Step 5: Derive session key
    const sessionKey = await deriveSessionKeyFromECDH(
      myEphemeralKeyPair.privateKey,
      initiatorEphemeralPublicKey,
      initMessage.nonce, // initiator nonce (sorted first)
      '', // my nonce not yet generated
      initMessage.initiatorId,
      myUserId
    );

    // Wait, I need to generate my nonce first before deriving the key
    // Let me fix this - generate nonce first
    const myNonce = generateNonce();
    const myTimestamp = Date.now();

    // Re-derive with both nonces
    const sessionKeyFinal = await deriveSessionKeyFromECDH(
      myEphemeralKeyPair.privateKey,
      initiatorEphemeralPublicKey,
      initMessage.nonce,
      myNonce,
      initMessage.initiatorId,
      myUserId
    );

    // Step 6: Store session key
    const conversationId = getConversationId(initMessage.initiatorId, myUserId);
    await storeSessionKey(conversationId, sessionKeyFinal, {
      conversationId,
      userId1: initMessage.initiatorId,
      userId2: myUserId,
      sessionId: initMessage.sessionId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + KEY_EXCHANGE_CONFIG.SESSION_KEY_EXPIRATION_DAYS * 24 * 60 * 60 * 1000),
      keyExchangeCompletedAt: new Date(), // Will be updated after confirmation
    });

    console.log('✅ Session key derived and stored');

    // Step 7: Delete my ephemeral private key (no longer needed)
    // Actually, we should keep it temporarily until confirmation is verified
    // Store it with session ID for cleanup later
    await storeEphemeralKey(initMessage.sessionId, myEphemeralKeyPair.privateKey);

    // Step 8: Sign response message
    const myPrivateKeyJwk = await getPrivateKey(myUserId);
    if (!myPrivateKeyJwk) {
      throw new Error('Private key not found. Please register again.');
    }
    const myECDSAPrivateKey = await importECDSAPrivateKey(myPrivateKeyJwk);

    const signature = await signResponseMessage(
      myECDSAPrivateKey,
      myEphemeralPublicKeyJwk,
      myNonce,
      myTimestamp,
      initMessage.initiatorId,
      myUserId,
      initMessage.nonce
    );

    // Step 9: Construct response message
    const responseMessage: KeyExchangeResponseMessage = {
      messageType: 'KEY_EXCHANGE_RESPONSE',
      sessionId: initMessage.sessionId,
      responderId: myUserId,
      initiatorId: initMessage.initiatorId,
      ephemeralPublicKey: myEphemeralPublicKeyJwk,
      nonce: myNonce,
      initiatorNonce: initMessage.nonce,
      timestamp: myTimestamp,
      signature,
    };

    console.log('✅ Key exchange response message created');
    return responseMessage;
  } catch (error) {
    console.error('❌ Failed to handle key exchange init:', error);
    throw error;
  }
}

/**
 * Handle key exchange response (Alice/Initiator side)
 *
 * Processes MESSAGE 2 and creates MESSAGE 3: KeyExchangeConfirm
 *
 * @param responseMessage - Received response message
 * @param myUserId - Initiator's user ID
 * @param responderPublicKeyJwk - Responder's ECDSA public key (from server)
 * @param myNonce - My original nonce from init message
 * @returns Promise<KeyExchangeConfirmMessage> - Confirmation message
 */
export async function handleKeyExchangeResponse(
  responseMessage: KeyExchangeResponseMessage,
  myUserId: string,
  responderPublicKeyJwk: string,
  myNonce: string
): Promise<KeyExchangeConfirmMessage> {
  try {
    console.log('🔐 Handling key exchange response from:', responseMessage.responderId);

    // Step 1: Verify timestamp
    if (!isTimestampValid(responseMessage.timestamp)) {
      throw new Error('Response message timestamp expired or invalid');
    }

    // Step 2: Verify my nonce was echoed correctly
    if (responseMessage.initiatorNonce !== myNonce) {
      throw new Error('Nonce mismatch in response message');
    }

    // Step 3: Verify signature
    const responderPublicKey = await importECDSAPublicKey(responderPublicKeyJwk);
    const signatureValid = await verifyResponseMessage(
      responderPublicKey,
      responseMessage.signature,
      responseMessage.ephemeralPublicKey,
      responseMessage.nonce,
      responseMessage.timestamp,
      myUserId,
      responseMessage.responderId,
      myNonce
    );

    if (!signatureValid) {
      throw new Error('Invalid signature on response message');
    }

    console.log('✅ Response message signature verified');

    // Step 4: Retrieve my ephemeral private key
    const myEphemeralPrivateKey = await getEphemeralKey(responseMessage.sessionId);
    if (!myEphemeralPrivateKey) {
      throw new Error('Ephemeral private key not found. Key exchange may have timed out.');
    }

    // Step 5: Import responder's ephemeral public key
    const responderEphemeralPublicKey = await importECDHPublicKey(responseMessage.ephemeralPublicKey);

    // Step 6: Derive session key
    const sessionKey = await deriveSessionKeyFromECDH(
      myEphemeralPrivateKey,
      responderEphemeralPublicKey,
      myNonce,
      responseMessage.nonce,
      myUserId,
      responseMessage.responderId
    );

    // Step 7: Store session key
    const conversationId = getConversationId(myUserId, responseMessage.responderId);
    await storeSessionKey(conversationId, sessionKey, {
      conversationId,
      userId1: myUserId,
      userId2: responseMessage.responderId,
      sessionId: responseMessage.sessionId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + KEY_EXCHANGE_CONFIG.SESSION_KEY_EXPIRATION_DAYS * 24 * 60 * 60 * 1000),
      keyExchangeCompletedAt: new Date(),
    });

    console.log('✅ Session key derived and stored');

    // Step 8: Delete ephemeral private key (no longer needed)
    await deleteEphemeralKey(responseMessage.sessionId);

    // Step 9: Compute confirmation tag
    const confirmTimestamp = Date.now();
    const confirmationTag = await computeConfirmationTag(
      sessionKey,
      myUserId,
      responseMessage.responderId,
      myNonce,
      responseMessage.nonce,
      confirmTimestamp
    );

    // Step 10: Construct confirmation message
    const confirmMessage: KeyExchangeConfirmMessage = {
      messageType: 'KEY_EXCHANGE_CONFIRM',
      sessionId: responseMessage.sessionId,
      initiatorId: myUserId,
      responderId: responseMessage.responderId,
      confirmationTag,
      initiatorNonce: myNonce,
      responderNonce: responseMessage.nonce,
      timestamp: confirmTimestamp,
    };

    console.log('✅ Key exchange confirmation message created');
    return confirmMessage;
  } catch (error) {
    console.error('❌ Failed to handle key exchange response:', error);
    throw error;
  }
}

/**
 * Handle key exchange confirmation (Bob/Responder side)
 *
 * Processes MESSAGE 3 and verifies mutual key agreement
 *
 * @param confirmMessage - Received confirmation message
 * @param myUserId - Responder's user ID
 * @returns Promise<boolean> - True if confirmation valid
 */
export async function handleKeyExchangeConfirm(
  confirmMessage: KeyExchangeConfirmMessage,
  myUserId: string
): Promise<boolean> {
  try {
    console.log('🔐 Handling key exchange confirmation from:', confirmMessage.initiatorId);

    // Step 1: Verify timestamp
    if (!isTimestampValid(confirmMessage.timestamp)) {
      console.error('⚠️ Confirmation message timestamp expired');
      return false;
    }

    // Step 2: Retrieve session key
    const conversationId = getConversationId(confirmMessage.initiatorId, myUserId);
    const metadata = await getSessionMetadata(conversationId);

    if (!metadata) {
      throw new Error('Session key not found. Key exchange incomplete.');
    }

    // Step 3: Re-import session key for verification
    // Actually, we need to get the actual CryptoKey, not just metadata
    const { getSessionKey } = await import('./sessionKeys');
    const sessionKey = await getSessionKey(conversationId);

    if (!sessionKey) {
      throw new Error('Session key not found in storage');
    }

    // Step 4: Compute expected confirmation tag
    const expectedTag = await computeConfirmationTag(
      sessionKey,
      confirmMessage.initiatorId,
      myUserId,
      confirmMessage.initiatorNonce,
      confirmMessage.responderNonce,
      confirmMessage.timestamp
    );

    // Step 5: Verify confirmation tag matches
    if (expectedTag !== confirmMessage.confirmationTag) {
      console.error('⚠️ Confirmation tag mismatch');
      return false;
    }

    console.log('✅ Key exchange confirmed! Mutual key agreement verified.');

    // Step 6: Delete ephemeral private key (cleanup)
    await deleteEphemeralKey(confirmMessage.sessionId);

    return true;
  } catch (error) {
    console.error('❌ Failed to handle key exchange confirmation:', error);
    return false;
  }
}

/**
 * Check if valid session key exists for conversation
 *
 * @param myUserId - Current user ID
 * @param peerUserId - Peer user ID
 * @returns Promise<boolean> - True if valid session key exists
 */
export async function hasValidSession(myUserId: string, peerUserId: string): Promise<boolean> {
  const conversationId = getConversationId(myUserId, peerUserId);
  const { hasValidSessionKey } = await import('./sessionKeys');
  return await hasValidSessionKey(conversationId);
}

/**
 * Check if session key is expired
 *
 * @param myUserId - Current user ID
 * @param peerUserId - Peer user ID
 * @returns Promise<boolean> - True if expired
 */
export async function isSessionExpired(myUserId: string, peerUserId: string): Promise<boolean> {
  const conversationId = getConversationId(myUserId, peerUserId);
  const { isSessionKeyExpired } = await import('./sessionKeys');
  return await isSessionKeyExpired(conversationId);
}
