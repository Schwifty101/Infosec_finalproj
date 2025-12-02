/**
 * WebSocket Event Type Definitions
 *
 * Defines all Socket.io event schemas for type-safe WebSocket communication
 */

/**
 * Message sent from client to server for delivery
 */
export interface MessageSendEvent {
  receiverId: string;
  message: {
    _id: string;
    senderId: string;
    receiverId: string;
    ciphertext: string;
    iv: string;
    authTag: string;
    nonce: string;
    sequenceNumber: number;
    timestamp: Date;
  };
}

/**
 * Message received from server
 */
export interface MessageReceiveEvent {
  _id: string;
  senderId: string;
  receiverId: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  nonce: string;
  sequenceNumber: number;
  timestamp: Date;
  receivedAt: number;
}

/**
 * Typing indicator event
 */
export interface TypingIndicatorEvent {
  senderId: string;
  typing: boolean;
}

/**
 * Message delivery confirmation
 */
export interface MessageDeliveredEvent {
  messageId: string;
  deliveredAt: number;
}

/**
 * Message stored (recipient offline)
 */
export interface MessageStoredEvent {
  messageId: string;
  status: 'offline';
}

/**
 * Message read receipt
 */
export interface MessageReadEvent {
  messageId: string;
  readBy: string;
  readAt: number;
}

/**
 * User online/offline status
 */
export interface UserStatusEvent {
  userId: string;
  online: boolean;
}

/**
 * Authentication events
 */
export interface AuthRegisterEvent {
  userId: string;
}

export interface AuthSuccessEvent {
  userId: string;
  timestamp: number;
}

/**
 * Status check events
 */
export interface StatusCheckEvent {
  userId: string;
}

export interface StatusResponseEvent {
  userId: string;
  online: boolean;
}

/**
 * Pending messages check
 */
export interface PendingMessagesEvent {
  message: string;
}

/**
 * Error event
 */
export interface SocketErrorEvent {
  message: string;
  code?: string;
}

/**
 * All WebSocket event types
 * Used for type-safe event emission and handling
 */
export interface WebSocketEvents {
  // Client -> Server
  'auth:register': AuthRegisterEvent;
  'message:send': MessageSendEvent;
  'typing:start': { receiverId: string };
  'typing:stop': { receiverId: string };
  'message:mark-read': { messageId: string; senderId: string };
  'status:check': StatusCheckEvent;

  // Server -> Client
  'auth:success': AuthSuccessEvent;
  'message:receive': MessageReceiveEvent;
  'message:delivered': MessageDeliveredEvent;
  'message:stored': MessageStoredEvent;
  'message:read': MessageReadEvent;
  'typing:indicator': TypingIndicatorEvent;
  'user:online': { userId: string };
  'user:offline': { userId: string };
  'status:response': StatusResponseEvent;
  'pending:check': PendingMessagesEvent;
  error: SocketErrorEvent;
}
