/**
 * GET /api/key-exchange/pending/:userId
 *
 * Retrieves pending key exchange requests for a user
 * Returns all initiated key exchanges where the user is the responder
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db/connection';
import { Collections, type UserDocument, type KeyExchangeDocument } from '@/lib/db/models';
import type { PendingKeyExchangesResponse } from '@/types';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ userId: string }> }
) {
  try {
    const { userId } = await params;

    if (!userId) {
      return NextResponse.json(
        {
          success: false,
          exchanges: [],
        } as PendingKeyExchangesResponse,
        { status: 400 }
      );
    }

    // Connect to database
    const { db } = await connectToDatabase();

    // Find all key exchange requests where:
    // - userId2 (responder) = current user
    // - status = 'initiated' (not yet responded)
    const keyExchangesCollection = db.collection<KeyExchangeDocument>(Collections.KEY_EXCHANGES);
    const pendingExchanges = await keyExchangesCollection
      .find({
        userId2: userId,
        status: 'initiated',
      })
      .toArray();

    // For each pending exchange, fetch the initiator's username
    const usersCollection = db.collection<UserDocument>(Collections.USERS);
    const exchangesWithUsernames = await Promise.all(
      pendingExchanges.map(async (exchange) => {
        // Find initiator user
        const initiator = await usersCollection.findOne({ _id: exchange.userId1 } as any);

        return {
          sessionId: exchange.sessionId,
          fromUserId: exchange.userId1,
          fromUsername: initiator?.username || 'Unknown User',
          createdAt: exchange.createdAt,
          initMessage: {
            messageType: 'KEY_EXCHANGE_INIT' as const,
            sessionId: exchange.sessionId,
            initiatorId: exchange.userId1,
            responderId: exchange.userId2,
            ephemeralPublicKey: exchange.initMessage?.ephemeralPublicKey || '',
            nonce: exchange.initMessage?.nonce || '',
            timestamp: exchange.initMessage?.timestamp.getTime() || 0,
            signature: exchange.initMessage?.signature || '',
          },
        };
      })
    );

    console.log(`✅ Retrieved ${exchangesWithUsernames.length} pending key exchanges for user ${userId}`);

    return NextResponse.json({
      success: true,
      exchanges: exchangesWithUsernames,
    } as PendingKeyExchangesResponse);
  } catch (error: any) {
    console.error('❌ Error retrieving pending key exchanges:', error);

    return NextResponse.json(
      {
        success: false,
        exchanges: [],
      } as PendingKeyExchangesResponse,
      { status: 500 }
    );
  }
}
