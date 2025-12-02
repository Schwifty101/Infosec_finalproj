/**
 * POST /api/key-exchange/confirm
 *
 * Confirms successful key exchange
 * Marks the session as complete
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import type {
  ConfirmKeyExchangeRequest,
  ConfirmKeyExchangeResponse,
  KeyExchangeDocument,
} from '@/types';
import { KEY_EXCHANGE_CONFIG } from '@/types/keyExchange';

export async function POST(request: NextRequest) {
  try {
    // Parse request body
    const body: ConfirmKeyExchangeRequest = await request.json();
    const { message } = body;

    // Validate message structure
    if (!message || message.messageType !== 'KEY_EXCHANGE_CONFIRM') {
      return NextResponse.json(
        {
          success: false,
          message: 'Invalid message format',
        } as ConfirmKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Validate required fields
    if (
      !message.sessionId ||
      !message.initiatorId ||
      !message.responderId ||
      !message.confirmationTag ||
      !message.initiatorNonce ||
      !message.responderNonce ||
      !message.timestamp
    ) {
      return NextResponse.json(
        {
          success: false,
          message: 'Missing required fields in confirmation message',
        } as ConfirmKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Validate timestamp
    const now = Date.now();
    const timeDiff = Math.abs(now - message.timestamp);
    if (timeDiff > KEY_EXCHANGE_CONFIG.TIMESTAMP_WINDOW_MS) {
      return NextResponse.json(
        {
          success: false,
          message: 'Timestamp expired or invalid',
        } as ConfirmKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Connect to database
    const { db } = await connectToDatabase();

    // Check session exists and is in correct state
    const keyExchangesCollection = db.collection<KeyExchangeDocument>(Collections.KEY_EXCHANGES);
    const session = await keyExchangesCollection.findOne({ sessionId: message.sessionId });

    if (!session) {
      return NextResponse.json(
        {
          success: false,
          message: 'Key exchange session not found',
        } as ConfirmKeyExchangeResponse,
        { status: 404 }
      );
    }

    if (session.status !== 'responded') {
      return NextResponse.json(
        {
          success: false,
          message: `Invalid session state: ${session.status}. Expected: responded`,
        } as ConfirmKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Verify user IDs match
    if (session.userId1 !== message.initiatorId || session.userId2 !== message.responderId) {
      return NextResponse.json(
        {
          success: false,
          message: 'User ID mismatch in confirmation message',
        } as ConfirmKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Update key exchange session to confirmed
    await keyExchangesCollection.updateOne(
      { sessionId: message.sessionId },
      {
        $set: {
          status: 'confirmed',
          confirmMessage: {
            confirmationTag: message.confirmationTag,
            timestamp: new Date(message.timestamp),
          },
          updatedAt: new Date(),
          completedAt: new Date(),
        },
      }
    );

    // Log successful key exchange completion
    await db.collection(Collections.LOGS).insertOne({
      type: 'key_exchange',
      userId: message.initiatorId,
      details: `Key exchange completed successfully with user ${message.responderId}. SessionId: ${message.sessionId}`,
      timestamp: new Date(),
      success: true,
    });

    console.log('✅ Key exchange confirmed and completed:', message.sessionId);

    return NextResponse.json({
      success: true,
      message: 'Key exchange confirmed successfully',
    } as ConfirmKeyExchangeResponse);
  } catch (error: any) {
    console.error('❌ Key exchange confirmation error:', error);

    return NextResponse.json(
      {
        success: false,
        message: error.message || 'Failed to confirm key exchange',
      } as ConfirmKeyExchangeResponse,
      { status: 500 }
    );
  }
}
