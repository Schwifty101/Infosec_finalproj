/**
 * GET /api/messages/conversation/:conversationId
 *
 * Retrieves paginated message history for a conversation
 * Uses cursor-based pagination for scalability
 * Returns encrypted messages (client-side decryption)
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import { ObjectId } from 'mongodb';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ conversationId: string }> }
) {
  try {
    const { conversationId } = await params;
    const { searchParams } = new URL(request.url);

    // Parse query parameters
    const before = searchParams.get('before'); // Cursor (MongoDB ObjectId)
    const limit = Math.min(
      parseInt(searchParams.get('limit') || '50', 10),
      100
    ); // Max 100 messages

    // Validate conversationId format
    if (!conversationId || !conversationId.includes('_')) {
      return NextResponse.json(
        {
          success: false,
          message: 'Invalid conversation ID format',
        },
        { status: 400 }
      );
    }

    // Parse conversationId to get user IDs
    const [userId1, userId2] = conversationId.split('_');

    if (!userId1 || !userId2) {
      return NextResponse.json(
        {
          success: false,
          message: 'Invalid conversation ID',
        },
        { status: 400 }
      );
    }

    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);

    // Build query to find messages in this conversation
    const query: any = {
      $or: [
        { senderId: userId1, receiverId: userId2 },
        { senderId: userId2, receiverId: userId1 },
      ],
    };

    // Add cursor for pagination (before this message ID)
    if (before) {
      try {
        query._id = { $lt: new ObjectId(before) };
      } catch (error) {
        return NextResponse.json(
          {
            success: false,
            message: 'Invalid cursor',
          },
          { status: 400 }
        );
      }
    }

    // Fetch messages (newest first)
    const messages = await messagesCollection
      .find(query)
      .sort({ _id: -1 }) // Descending order (newest first)
      .limit(limit)
      .toArray();

    // Log message access
    const userId = searchParams.get('userId') || userId1; // Get userId from query param or default to userId1
    await db.collection(Collections.LOGS).insertOne({
      type: 'message_access',
      userId: userId,
      conversationId: conversationId,
      details: `User accessed conversation messages`,
      timestamp: new Date(),
      success: true,
      messageCount: messages.length,
    });

    // Map messages to clean format
    const formattedMessages = messages.map((msg) => ({
      _id: msg._id.toString(),
      senderId: msg.senderId,
      receiverId: msg.receiverId,
      ciphertext: msg.ciphertext,
      iv: msg.iv,
      authTag: msg.authTag,
      nonce: msg.nonce,
      sequenceNumber: msg.sequenceNumber,
      timestamp: msg.timestamp,
      delivered: msg.delivered || false,
      deliveredAt: msg.deliveredAt || null,
      read: msg.read || false,
      readAt: msg.readAt || null,
    }));

    // Check if there are more messages
    const hasMore = messages.length === limit;

    // Get cursor for next page (if more messages exist)
    const nextCursor =
      messages.length > 0
        ? messages[messages.length - 1]._id.toString()
        : null;

    console.log(
      `✅ Retrieved ${messages.length} messages for conversation ${conversationId}`
    );

    return NextResponse.json(
      {
        success: true,
        messages: formattedMessages,
        hasMore,
        nextCursor,
        count: messages.length,
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('❌ Get conversation messages error:', error);

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to retrieve messages',
        error: error.message,
      },
      { status: 500 }
    );
  }
}
