/**
 * POST /api/messages/send
 *
 * Stores encrypted message in MongoDB
 * Validates sequence numbers for replay/reorder protection
 * Logs security events
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import { getLastSequenceNumber, isNonceUsed, storeNonce } from '@/lib/crypto/messaging-server';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const {
      senderId,
      receiverId,
      ciphertext,
      iv,
      authTag,
      nonce,
      sequenceNumber,
    } = body;

    // Validate required fields
    if (
      !senderId ||
      !receiverId ||
      !ciphertext ||
      !iv ||
      !authTag ||
      !nonce ||
      sequenceNumber === undefined
    ) {
      return NextResponse.json(
        {
          success: false,
          message: 'Missing required fields',
        },
        { status: 400 }
      );
    }

    // Validate senderId and receiverId are different
    if (senderId === receiverId) {
      return NextResponse.json(
        {
          success: false,
          message: 'Cannot send message to yourself',
        },
        { status: 400 }
      );
    }

    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);
    const logsCollection = db.collection(Collections.LOGS);

    // Create conversation ID (deterministic)
    const conversationId = [senderId, receiverId].sort().join('_');

    // Check nonce uniqueness (replay protection)
    const nonceExists = await isNonceUsed(nonce);
    if (nonceExists) {
      console.warn(`⚠️ Replay attack detected: Duplicate nonce from ${senderId}`);

      // Log security event
      await logsCollection.insertOne({
        type: 'replay_detected',
        userId: senderId,
        details: `Duplicate nonce detected in message`,
        nonce,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: 'Replay attack detected: Duplicate nonce',
        },
        { status: 400 }
      );
    }

    // Validate sequence number (prevent reordering)
    const lastSeq = await getLastSequenceNumber(conversationId, senderId);
    const expectedSeq = lastSeq + 1;

    if (sequenceNumber !== expectedSeq) {
      console.warn(
        `⚠️ Invalid sequence number: expected ${expectedSeq}, got ${sequenceNumber}`
      );

      // Log security event
      await logsCollection.insertOne({
        type: 'invalid_sequence',
        userId: senderId,
        details: `Sequence number mismatch: expected ${expectedSeq}, received ${sequenceNumber}`,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: `Invalid sequence number: expected ${expectedSeq}`,
        },
        { status: 400 }
      );
    }

    // Insert message into database
    const result = await messagesCollection.insertOne({
      senderId,
      receiverId,
      ciphertext,
      iv,
      authTag,
      nonce,
      sequenceNumber,
      timestamp: new Date(),
      delivered: false,
      deliveredAt: null,
      read: false,
      readAt: null,
    });

    const messageId = result.insertedId.toString();

    // Store nonce for replay protection
    await storeNonce(nonce, senderId, messageId);

    // Log successful message send
    await logsCollection.insertOne({
      type: 'message_sent',
      userId: senderId,
      details: `Encrypted message sent to ${receiverId}`,
      messageId,
      timestamp: new Date(),
      success: true,
    });

    console.log(
      `✅ Message ${messageId} stored: ${senderId} -> ${receiverId} (seq: ${sequenceNumber})`
    );

    return NextResponse.json(
      {
        success: true,
        messageId,
        timestamp: new Date().toISOString(),
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('❌ Send message error:', error);

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to send message',
        error: error.message,
      },
      { status: 500 }
    );
  }
}
