/**
 * Database collection names and utility functions
 * No Mongoose - using MongoDB native driver for simplicity
 */

/**
 * Collection names used in the application
 */
export const Collections = {
  USERS: 'users',
  MESSAGES: 'messages',
  FILES: 'files',
  LOGS: 'security_logs',
  KEY_EXCHANGES: 'key_exchanges',
  NONCES: 'nonces',
} as const;

/**
 * User document structure in MongoDB
 *
 * Fields:
 * - username: Unique username for authentication
 * - passwordHash: bcrypt hashed password
 * - publicKey: User's public key (JWK format)
 * - createdAt: Account creation timestamp
 */
export interface UserDocument {
  username: string;
  passwordHash: string;
  publicKey?: string;
  createdAt: Date;
}

/**
 * Message document structure
 * Stores encrypted message data
 */
export interface MessageDocument {
  senderId: string;
  receiverId: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  nonce: string;
  timestamp: Date;
  sequenceNumber: number;
  delivered: boolean;
  deliveredAt?: Date | null;
  read: boolean;
  readAt?: Date | null;
}

/**
 * File document structure
 * Stores encrypted file metadata and data
 */
export interface FileDocument {
  senderId: string;
  receiverId: string;
  filename: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  size: number;
  uploadedAt: Date;
}

/**
 * Security log document structure
 * Tracks authentication attempts, key exchanges, and security events
 */
export interface SecurityLogDocument {
  type: 'auth' | 'key_exchange' | 'decrypt_fail' | 'replay_detected' | 'invalid_signature' | 'metadata_access';
  userId?: string;
  details: string;
  timestamp: Date;
  ipAddress?: string;
  success?: boolean;
}

/**
 * Key exchange status types
 */
export type KeyExchangeStatus = 'initiated' | 'responded' | 'confirmed' | 'failed';

/**
 * Key exchange document structure (Phase 2 - Enhanced)
 * Stores complete key exchange protocol state
 */
export interface KeyExchangeDocument {
  sessionId: string;           // UUID for unique session identification
  userId1: string;             // Initiator user ID
  userId2: string;             // Responder user ID
  status: KeyExchangeStatus;   // Current status of key exchange

  // Init message data
  initMessage?: {
    ephemeralPublicKey: string;
    nonce: string;
    timestamp: Date;
    signature: string;
  };

  // Response message data
  responseMessage?: {
    ephemeralPublicKey: string;
    nonce: string;
    timestamp: Date;
    signature: string;
  };

  // Confirmation message data
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
 * Nonce document structure (Phase 2 - NEW)
 * Used for replay attack prevention
 * Nonces are unique random values that can only be used once
 */
export interface NonceDocument {
  nonce: string;               // Unique nonce value (Base64)
  userId: string;              // User who generated the nonce
  sessionId: string;           // Associated key exchange session
  createdAt: Date;
  expiresAt: Date;             // TTL: 24 hours
}
