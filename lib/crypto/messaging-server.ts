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
  conversationId: string,
  senderId?: string
): Promise<number> {
  try {
    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    // Parse conversationId to get user IDs (format: "userId1_userId2")
    const parts = conversationId.split('_');
    if (parts.length !== 2) {
      console.error('Invalid conversation ID format:', conversationId);
      return 1;
    }
    const [userId1, userId2] = parts;

    // If senderId provided, get sequence for specific sender
    // Otherwise, get overall conversation sequence (for backward compatibility)
    if (senderId) {
      console.log(`🔍 getNextSequenceNumber: Looking for messages from ${senderId} in conversation ${conversationId}`);

      const latestMessage = await messagesCollection
        .findOne(
          {
            senderId: senderId,
            $or: [
              { receiverId: userId1 },
              { receiverId: userId2 },
            ],
          },
          { sort: { sequenceNumber: -1 } }
        );

      if (!latestMessage || latestMessage.sequenceNumber === undefined) {
        console.log(`🔍 getNextSequenceNumber: No messages from ${senderId}, returning 1`);
        return 1;
      }

      console.log(`🔍 getNextSequenceNumber: Found message from ${senderId} with seq=${latestMessage.sequenceNumber}, returning ${latestMessage.sequenceNumber + 1}`);
      return latestMessage.sequenceNumber + 1;
    }

    // Legacy: Get conversation-wide sequence (deprecated)
    console.log(`🔍 getNextSequenceNumber: Looking for messages in conversation ${conversationId}`);

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
      console.log(`🔍 getNextSequenceNumber: No messages found, returning 1`);
      return 1;
    }

    console.log(`🔍 getNextSequenceNumber: Found message with seq=${latestMessage.sequenceNumber}, returning ${latestMessage.sequenceNumber + 1}`);
    return latestMessage.sequenceNumber + 1;
  } catch (error) {
    console.error('Failed to get sequence number:', error);
    return 1;
  }
}

/**
 * Get last sequence number for a conversation
 * Used for validation on server-side
 * Note: Sequence numbers are per-conversation, not per-sender
 *
 * @param conversationId - Deterministic conversation ID
 * @param senderId - Sender's user ID (unused, kept for compatibility)
 * @returns Promise<number> - Last sequence number in this conversation
 */
export async function getLastSequenceNumber(
  conversationId: string,
  senderId: string
): Promise<number> {
  try {
    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    // Parse conversationId to get user IDs
    const parts = conversationId.split('_');
    if (parts.length !== 2) {
      console.error('Invalid conversation ID format:', conversationId);
      return 0;
    }
    const [userId1, userId2] = parts;

    console.log(`🔍 getLastSequenceNumber: Looking for messages from ${senderId} in conversation ${conversationId}`);

    // Find latest message from THIS SENDER in this conversation
    // Each sender has their own sequence counter
    const latestMessage = await messagesCollection
      .findOne(
        {
          senderId: senderId,
          $or: [
            { receiverId: userId1 },
            { receiverId: userId2 },
          ],
        },
        { sort: { sequenceNumber: -1 } }
      );

    if (!latestMessage || latestMessage.sequenceNumber === undefined) {
      console.log(`🔍 getLastSequenceNumber: No messages from ${senderId} found, returning 0`);
      return 0; // No messages yet from this sender
    }

    console.log(`🔍 getLastSequenceNumber: Found message from ${senderId} with seq=${latestMessage.sequenceNumber}`);
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
