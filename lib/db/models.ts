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
 * Key exchange document structure
 * Tracks key exchange operations between users
 */
export interface KeyExchangeDocument {
  userId1: string;
  userId2: string;
  sessionKeyId: string;
  timestamp: Date;
  signatureVerified: boolean;
}
