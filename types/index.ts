/**
 * Type definitions for the Secure E2E Messaging System
 */

// User types
export interface IUser {
  _id: string;
  username: string;
  passwordHash: string;
  publicKey: string;
  createdAt: Date;
}

// Message types
export interface IMessage {
  _id: string;
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

// File types
export interface IFile {
  _id: string;
  senderId: string;
  receiverId: string;
  filename: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  size: number;
  uploadedAt: Date;
}

// Key Exchange types
export interface IKeyExchange {
  userId1: string;
  userId2: string;
  sessionKeyId: string;
  timestamp: Date;
  signatureVerified: boolean;
}

// Log types
export interface ISecurityLog {
  _id: string;
  type: 'auth' | 'key_exchange' | 'decrypt_fail' | 'replay_detected' | 'invalid_signature' | 'metadata_access';
  userId?: string;
  details: string;
  timestamp: Date;
  ipAddress?: string;
}

// API Response types
export interface IApiResponse {
  success: boolean;
  message: string;
}

export interface IRegisterResponse extends IApiResponse {
  userId?: string;
}

export interface ILoginResponse extends IApiResponse {
  userId?: string;
  username?: string;
  publicKey?: string;
}

export interface IKeyStoreResponse extends IApiResponse {}

export interface IKeyRetrieveResponse extends IApiResponse {
  publicKey?: string;
  username?: string;
}

// Export all key exchange types from keyExchange.ts
export * from './keyExchange';

// Export all WebSocket event types from websocket.ts
export * from './websocket';
