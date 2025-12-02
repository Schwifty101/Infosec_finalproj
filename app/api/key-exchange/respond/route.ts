/**
 * POST /api/key-exchange/respond
 *
 * Responds to a key exchange initiation
 * Validates the response and updates the key exchange session
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import type {
  RespondKeyExchangeRequest,
  RespondKeyExchangeResponse,
  KeyExchangeDocument,
  NonceDocument,
} from '@/types';
import { KEY_EXCHANGE_CONFIG } from '@/types/keyExchange';

export async function POST(request: NextRequest) {
  try {
    // Parse request body
    const body: RespondKeyExchangeRequest = await request.json();
    const { message } = body;

    // Validate message structure
    if (!message || message.messageType !== 'KEY_EXCHANGE_RESPONSE') {
      return NextResponse.json(
        {
          success: false,
          message: 'Invalid message format',
        } as RespondKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Validate required fields
    if (
      !message.sessionId ||
      !message.responderId ||
      !message.initiatorId ||
      !message.ephemeralPublicKey ||
      !message.nonce ||
      !message.initiatorNonce ||
      !message.timestamp ||
      !message.signature
    ) {
      return NextResponse.json(
        {
          success: false,
          message: 'Missing required fields in response message',
        } as RespondKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Validate timestamp
    const now = Date.now();
    const timeDiff = Math.abs(now - message.timestamp);
    if (timeDiff > KEY_EXCHANGE_CONFIG.TIMESTAMP_WINDOW_MS) {
      // Connect to database for logging
      const { db } = await connectToDatabase();

      // Log expired timestamp
      await db.collection(Collections.LOGS).insertOne({
        type: 'expired_timestamp',
        userId: message.responderId,
        details: `Timestamp expired in key exchange response. Time diff: ${timeDiff}ms`,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: 'Timestamp expired or invalid',
        } as RespondKeyExchangeResponse,
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
        } as RespondKeyExchangeResponse,
        { status: 404 }
      );
    }

    if (session.status !== 'initiated') {
      return NextResponse.json(
        {
          success: false,
          message: `Invalid session state: ${session.status}. Expected: initiated`,
        } as RespondKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Verify user IDs match
    if (session.userId2 !== message.responderId || session.userId1 !== message.initiatorId) {
      return NextResponse.json(
        {
          success: false,
          message: 'User ID mismatch in response message',
        } as RespondKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Check nonce uniqueness
    const noncesCollection = db.collection<NonceDocument>(Collections.NONCES);
    const existingNonce = await noncesCollection.findOne({ nonce: message.nonce });

    if (existingNonce) {
      // Log replay attack
      await db.collection(Collections.LOGS).insertOne({
        type: 'replay_detected',
        userId: message.responderId,
        details: `Duplicate nonce detected in key exchange response. SessionId: ${message.sessionId}`,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: 'Nonce already used (replay attack detected)',
        } as RespondKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Store nonce
    const nonceExpiresAt = new Date();
    nonceExpiresAt.setHours(nonceExpiresAt.getHours() + KEY_EXCHANGE_CONFIG.NONCE_TTL_HOURS);

    await noncesCollection.insertOne({
      nonce: message.nonce,
      userId: message.responderId,
      sessionId: message.sessionId,
      createdAt: new Date(),
      expiresAt: nonceExpiresAt,
    } as NonceDocument);

    // Update key exchange session
    await keyExchangesCollection.updateOne(
      { sessionId: message.sessionId },
      {
        $set: {
          status: 'responded',
          responseMessage: {
            ephemeralPublicKey: message.ephemeralPublicKey,
            nonce: message.nonce,
            timestamp: new Date(message.timestamp),
            signature: message.signature,
          },
          updatedAt: new Date(),
        },
      }
    );

    // Log successful response
    await db.collection(Collections.LOGS).insertOne({
      type: 'key_exchange',
      userId: message.responderId,
      details: `Key exchange response sent to user ${message.initiatorId}. SessionId: ${message.sessionId}`,
      timestamp: new Date(),
      success: true,
    });

    console.log('✅ Key exchange response recorded:', message.sessionId);

    return NextResponse.json({
      success: true,
      message: 'Key exchange response recorded successfully',
    } as RespondKeyExchangeResponse);
  } catch (error: any) {
    console.error('❌ Key exchange response error:', error);

    return NextResponse.json(
      {
        success: false,
        message: error.message || 'Failed to record key exchange response',
      } as RespondKeyExchangeResponse,
      { status: 500 }
    );
  }
}
