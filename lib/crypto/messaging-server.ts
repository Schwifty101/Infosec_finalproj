/**
 * Message Encryption/Decryption - SERVER-SIDE ONLY
 *
 * Server-side database operations for message handling
 *
 * This file contains functions that interact with MongoDB
 * and should ONLY be used in API routes and server components
 *
 * For client-side encryption/decryption, use messaging-client.ts
 */

import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';

/**
 * Get next sequence number for a conversation
 * Retrieves from MongoDB or starts at 1
 *
 * @param conversationId - Deterministic conversation ID
 * @returns Promise<number> - Next sequence number to use
 */
export async function getNextSequenceNumber(
  conversationId: string
): Promise<number> {
  try {
    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    // Parse conversationId to get user IDs
    const [userId1, userId2] = conversationId.split('_').sort();

    // Find latest message in conversation
    const latestMessage = await messagesCollection
      .findOne(
        {
          $or: [
            { senderId: userId1, receiverId: userId2 },
            { senderId: userId2, receiverId: userId1 },
          ],
        },
        { sort: { sequenceNumber: -1 } }
      );

    if (!latestMessage || latestMessage.sequenceNumber === undefined) {
      // First message in conversation
      return 1;
    }

    return latestMessage.sequenceNumber + 1;
  } catch (error) {
    console.error('Failed to get sequence number:', error);
    // Default to 1 if error
    return 1;
  }
}

/**
 * Get last sequence number for a conversation
 * Used for validation on server-side
 *
 * @param conversationId - Deterministic conversation ID
 * @param senderId - Sender's user ID
 * @returns Promise<number> - Last sequence number from this sender
 */
export async function getLastSequenceNumber(
  conversationId: string,
  senderId: string
): Promise<number> {
  try {
    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    const [userId1, userId2] = conversationId.split('_').sort();

    // Find latest message from this sender in this conversation
    const latestMessage = await messagesCollection
      .findOne(
        {
          senderId,
          $or: [
            { senderId: userId1, receiverId: userId2 },
            { senderId: userId2, receiverId: userId1 },
          ],
        },
        { sort: { sequenceNumber: -1 } }
      );

    if (!latestMessage || latestMessage.sequenceNumber === undefined) {
      return 0; // No messages yet
    }

    return latestMessage.sequenceNumber;
  } catch (error) {
    console.error('Failed to get last sequence number:', error);
    return 0;
  }
}

/**
 * Check if nonce has been used before (replay protection)
 * Server-side only - checks MongoDB nonces collection
 *
 * @param nonce - Base64 nonce to check
 * @returns Promise<boolean> - True if nonce has been used
 */
export async function isNonceUsed(nonce: string): Promise<boolean> {
  try {
    const db = await getDatabase();
    const noncesCollection = db.collection(Collections.NONCES);

    const existingNonce = await noncesCollection.findOne({ nonce });

    return existingNonce !== null;
  } catch (error) {
    console.error('Failed to check nonce:', error);
    return false; // Fail open (assume not used)
  }
}

/**
 * Store nonce to prevent replay attacks
 * Server-side only - stores in MongoDB with TTL
 *
 * @param nonce - Base64 nonce
 * @param userId - User ID who generated the nonce
 * @param messageId - Associated message ID
 * @returns Promise<void>
 */
export async function storeNonce(
  nonce: string,
  userId: string,
  messageId: string
): Promise<void> {
  try {
    const db = await getDatabase();
    const noncesCollection = db.collection(Collections.NONCES);

    await noncesCollection.insertOne({
      nonce,
      userId,
      messageId,
      createdAt: new Date(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours TTL
    });

    console.log('✅ Nonce stored for replay protection');
  } catch (error) {
    console.error('Failed to store nonce:', error);
    // Non-fatal - continue processing
  }
}

// Re-export client-side types for convenience
export type { EncryptedMessage } from './messaging-client';
