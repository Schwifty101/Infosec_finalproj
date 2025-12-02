/**
 * GET /api/conversations
 *
 * Lists all conversations for the authenticated user
 * Returns conversation metadata with last message preview and unread count
 * Uses MongoDB aggregation for efficient querying
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';

export async function GET(request: NextRequest) {
  try {
    // Get userId from request headers or query params
    const userId =
      request.headers.get('x-user-id') ||
      new URL(request.url).searchParams.get('userId');

    if (!userId) {
      return NextResponse.json(
        {
          success: false,
          message: 'User ID required',
        },
        { status: 401 }
      );
    }

    const db = await getDatabase();
    const messagesCollection = db.collection(Collections.MESSAGES);
    const usersCollection = db.collection(Collections.USERS);

    // Aggregate conversations with last message and unread count
    const conversations = await messagesCollection
      .aggregate([
        {
          // Match messages where user is sender or receiver
          $match: {
            $or: [{ senderId: userId }, { receiverId: userId }],
          },
        },
        {
          // Sort by timestamp (newest first)
          $sort: { timestamp: -1 },
        },
        {
          // Group by conversation (deterministic peer pairing)
          $group: {
            _id: {
              $concat: [
                {
                  $cond: [
                    { $lt: ['$senderId', '$receiverId'] },
                    '$senderId',
                    '$receiverId',
                  ],
                },
                '_',
                {
                  $cond: [
                    { $lt: ['$senderId', '$receiverId'] },
                    '$receiverId',
                    '$senderId',
                  ],
                },
              ],
            },
            lastMessage: { $first: '$$ROOT' },
            unreadCount: {
              $sum: {
                $cond: [
                  {
                    $and: [
                      { $eq: ['$receiverId', userId] },
                      { $eq: ['$read', false] },
                    ],
                  },
                  1,
                  0,
                ],
              },
            },
            messageCount: { $sum: 1 },
          },
        },
        {
          // Sort by last message timestamp
          $sort: { 'lastMessage.timestamp': -1 },
        },
        {
          // Limit to recent conversations
          $limit: 50,
        },
      ])
      .toArray();

    // Enrich with peer user information
    const enrichedConversations = await Promise.all(
      conversations.map(async (conv) => {
        const conversationId = conv._id;
        const [userId1, userId2] = conversationId.split('_');

        // Determine peer user ID
        const peerUserId = userId1 === userId ? userId2 : userId1;

        // Fetch peer user info
        const peerUser = await usersCollection.findOne(
          { _id: peerUserId },
          { projection: { username: 1, publicKey: 1 } }
        );

        return {
          conversationId,
          peerUserId,
          peerUsername: peerUser?.username || 'Unknown User',
          lastMessage: {
            _id: conv.lastMessage._id.toString(),
            senderId: conv.lastMessage.senderId,
            receiverId: conv.lastMessage.receiverId,
            ciphertext: conv.lastMessage.ciphertext,
            iv: conv.lastMessage.iv,
            authTag: conv.lastMessage.authTag,
            nonce: conv.lastMessage.nonce,
            sequenceNumber: conv.lastMessage.sequenceNumber,
            timestamp: conv.lastMessage.timestamp,
            delivered: conv.lastMessage.delivered || false,
            read: conv.lastMessage.read || false,
          },
          unreadCount: conv.unreadCount,
          messageCount: conv.messageCount,
        };
      })
    );

    console.log(
      `✅ Retrieved ${enrichedConversations.length} conversations for user ${userId}`
    );

    return NextResponse.json(
      {
        success: true,
        conversations: enrichedConversations,
        count: enrichedConversations.length,
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('❌ Get conversations error:', error);

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to retrieve conversations',
        error: error.message,
      },
      { status: 500 }
    );
  }
}
