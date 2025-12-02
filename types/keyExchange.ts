/**
 * Type definitions for AECDH-ECDSA Key Exchange Protocol
 *
 * Protocol Overview:
 * - 3-message authenticated ECDH key exchange
 * - ECDSA signatures for authentication
 * - HKDF-SHA256 for session key derivation
 * - Nonces and timestamps for replay protection
 */

// ============================================================================
// Key Exchange Message Types
// ============================================================================

/**
 * Message 1: Key Exchange Initiation
 * Sent by initiator (Alice) to responder (Bob)
 */
export interface KeyExchangeInitMessage {
  messageType: 'KEY_EXCHANGE_INIT';
  sessionId: string;                 // UUID v4 for unique session identification
  initiatorId: string;               // Alice's user ID
  responderId: string;                // Bob's user ID
  ephemeralPublicKey: string;        // Alice's ephemeral ECDH public key (JWK format)
  nonce: string;                     // Base64 encoded random nonce (16 bytes)
  timestamp: number;                 // Unix timestamp in milliseconds
  signature: string;                 // Base64 ECDSA signature over message payload
}

/**
 * Message 2: Key Exchange Response
 * Sent by responder (Bob) back to initiator (Alice)
 */
export interface KeyExchangeResponseMessage {
  messageType: 'KEY_EXCHANGE_RESPONSE';
  sessionId: string;                 // Same session ID from init message
  responderId: string;                // Bob's user ID
  initiatorId: string;               // Alice's user ID
  ephemeralPublicKey: string;        // Bob's ephemeral ECDH public key (JWK format)
  nonce: string;                     // Bob's nonce
  initiatorNonce: string;            // Echo of Alice's nonce (binding)
  timestamp: number;                 // Unix timestamp in milliseconds
  signature: string;                 // Base64 ECDSA signature over message payload
}

/**
 * Message 3: Key Exchange Confirmation
 * Sent by initiator (Alice) to confirm mutual key derivation
 */
export interface KeyExchangeConfirmMessage {
  messageType: 'KEY_EXCHANGE_CONFIRM';
  sessionId: string;                 // Same session ID
  initiatorId: string;               // Alice's user ID
  responderId: string;                // Bob's user ID
  confirmationTag: string;           // Base64 HMAC-SHA256 over session key
  initiatorNonce: string;            // Alice's nonce
  responderNonce: string;            // Bob's nonce
  timestamp: number;                 // Unix timestamp in milliseconds
}

/**
 * Union type for all key exchange messages
 */
export type KeyExchangeMessage =
  | KeyExchangeInitMessage
  | KeyExchangeResponseMessage
  | KeyExchangeConfirmMessage;

// ============================================================================
// Session Key Metadata
// ============================================================================

/**
 * Metadata for stored session keys
 * Used in IndexedDB for managing session key lifecycle
 */
export interface SessionMetadata {
  conversationId: string;            // Deterministic ID: sorted user IDs concatenated
  userId1: string;                   // First user ID (sorted)
  userId2: string;                   // Second user ID (sorted)
  sessionId: string;                 // UUID of the key exchange session
  createdAt: Date;                   // When session key was created
  expiresAt: Date;                   // When session key expires (30 days from creation)
  keyExchangeCompletedAt: Date;      // When key exchange completed
  isExpired?: boolean;               // Computed property for expiration check
}

/**
 * Extended session key data stored in IndexedDB
 */
export interface SessionKeyData extends SessionMetadata {
  sessionKey: CryptoKey;             // AES-256-GCM session key
}

// ============================================================================
// Key Exchange State & Status
// ============================================================================

/**
 * Status of key exchange process
 */
export type KeyExchangeStatus =
  | 'initiated'    // Init message sent
  | 'responded'    // Response message sent
  | 'confirmed'    // Confirmation received and verified
  | 'failed';      // Key exchange failed (signature/verification error)

/**
 * Key exchange session document (MongoDB)
 */
export interface KeyExchangeDocument {
  _id?: string;
  sessionId: string;
  userId1: string;                   // Initiator
  userId2: string;                   // Responder
  status: KeyExchangeStatus;

  // Message data
  initMessage?: {
    ephemeralPublicKey: string;
    nonce: string;
    timestamp: Date;
    signature: string;
  };

  responseMessage?: {
    ephemeralPublicKey: string;
    nonce: string;
    timestamp: Date;
    signature: string;
  };

  confirmMessage?: {
    confirmationTag: string;
    timestamp: Date;
  };

  // Timestamps
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
}

/**
 * Nonce document for replay protection (MongoDB)
 */
export interface NonceDocument {
  _id?: string;
  nonce: string;                     // Unique nonce value
  userId: string;                    // User who generated the nonce
  sessionId: string;                 // Associated key exchange session
  createdAt: Date;
  expiresAt: Date;                   // TTL: 24 hours
}

// ============================================================================
// API Request/Response Types
// ============================================================================

/**
 * Request body for initiating key exchange
 */
export interface InitiateKeyExchangeRequest {
  message: KeyExchangeInitMessage;
}

/**
 * Response for initiate key exchange
 */
export interface InitiateKeyExchangeResponse {
  success: boolean;
  message: string;
  sessionId?: string;
}

/**
 * Request body for responding to key exchange
 */
export interface RespondKeyExchangeRequest {
  message: KeyExchangeResponseMessage;
}

/**
 * Response for respond key exchange
 */
export interface RespondKeyExchangeResponse {
  success: boolean;
  message: string;
}

/**
 * Request body for confirming key exchange
 */
export interface ConfirmKeyExchangeRequest {
  message: KeyExchangeConfirmMessage;
}

/**
 * Response for confirm key exchange
 */
export interface ConfirmKeyExchangeResponse {
  success: boolean;
  message: string;
}

/**
 * Response for getting pending key exchange requests
 */
export interface PendingKeyExchangesResponse {
  success: boolean;
  exchanges: Array<{
    sessionId: string;
    fromUserId: string;
    fromUsername: string;
    createdAt: Date;
    initMessage: KeyExchangeInitMessage;
  }>;
}

/**
 * Response for getting key exchange status
 */
export interface KeyExchangeStatusResponse {
  success: boolean;
  status: KeyExchangeStatus;
  createdAt: Date;
  updatedAt: Date;
  completedAt?: Date;
}

// ============================================================================
// Error Types
// ============================================================================

/**
 * Key exchange error types
 */
export type KeyExchangeErrorType =
  | 'INVALID_SIGNATURE'
  | 'EXPIRED_TIMESTAMP'
  | 'DUPLICATE_NONCE'
  | 'INVALID_MESSAGE_FORMAT'
  | 'SESSION_NOT_FOUND'
  | 'INVALID_SESSION_STATE'
  | 'CONFIRMATION_FAILED'
  | 'ECDH_FAILED'
  | 'KEY_DERIVATION_FAILED';

/**
 * Key exchange error
 */
export interface KeyExchangeError {
  type: KeyExchangeErrorType;
  message: string;
  details?: any;
}

// ============================================================================
// Protocol Configuration
// ============================================================================

/**
 * Protocol configuration constants
 */
export const KEY_EXCHANGE_CONFIG = {
  TIMESTAMP_WINDOW_MS: 5 * 60 * 1000,        // 5 minutes
  NONCE_LENGTH_BYTES: 16,                     // 16 bytes (128 bits)
  SESSION_KEY_EXPIRATION_DAYS: 30,            // 30 days
  NONCE_TTL_HOURS: 24,                        // 24 hours
  POLL_INTERVAL_MS: 10 * 1000,                // 10 seconds
  HKDF_INFO: 'AECDH-ECDSA-SESSION-KEY',       // HKDF info string
  CONFIRMATION_PREFIX: 'KEY-CONFIRM',         // Confirmation tag prefix
} as const;
