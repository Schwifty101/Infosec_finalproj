/**
 * POST /api/key-exchange/initiate
 *
 * Initiates a key exchange session
 * Stores the init message and performs security checks:
 * - Timestamp validation (within 5 minute window)
 * - Nonce uniqueness (replay protection)
 * - Message structure validation
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import type {
  InitiateKeyExchangeRequest,
  InitiateKeyExchangeResponse,
  KeyExchangeDocument,
  NonceDocument,
} from '@/types';
import { KEY_EXCHANGE_CONFIG } from '@/types/keyExchange';

export async function POST(request: NextRequest) {
  try {
    // Parse request body
    const body: InitiateKeyExchangeRequest = await request.json();
    const { message } = body;

    // Validate message structure
    if (!message || message.messageType !== 'KEY_EXCHANGE_INIT') {
      return NextResponse.json(
        {
          success: false,
          message: 'Invalid message format',
        } as InitiateKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Validate required fields
    if (
      !message.sessionId ||
      !message.initiatorId ||
      !message.responderId ||
      !message.ephemeralPublicKey ||
      !message.nonce ||
      !message.timestamp ||
      !message.signature
    ) {
      return NextResponse.json(
        {
          success: false,
          message: 'Missing required fields in init message',
        } as InitiateKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Validate timestamp (must be within 5 minute window)
    const now = Date.now();
    const timeDiff = Math.abs(now - message.timestamp);
    if (timeDiff > KEY_EXCHANGE_CONFIG.TIMESTAMP_WINDOW_MS) {
      // Connect to database for logging
      const { db } = await connectToDatabase();

      // Log expired timestamp
      await db.collection(Collections.LOGS).insertOne({
        type: 'expired_timestamp',
        userId: message.initiatorId,
        details: `Timestamp expired in key exchange init. Time diff: ${timeDiff}ms`,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: 'Timestamp expired or invalid',
        } as InitiateKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Connect to database
    const { db } = await connectToDatabase();

    // Check for existing active key exchange sessions (prevent parallel exchanges)
    const keyExchangesCollection = db.collection<KeyExchangeDocument>(Collections.KEY_EXCHANGES);

    const existingSession = await keyExchangesCollection.findOne({
      $or: [
        { userId1: message.initiatorId, userId2: message.responderId },
        { userId1: message.responderId, userId2: message.initiatorId },
      ],
      status: { $in: ['initiated', 'responded'] }, // Active but not confirmed
      createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) }, // Within 5 min
    });

    if (existingSession) {
      console.log('⚠️ Active key exchange already exists:', existingSession.sessionId);

      return NextResponse.json(
        {
          success: false,
          message: 'Active key exchange already in progress between these users. ' +
            'Please wait for current exchange to complete or expire.',
          existingSessionId: existingSession.sessionId,
        } as InitiateKeyExchangeResponse,
        { status: 409 } // Conflict
      );
    }

    // Check nonce uniqueness (replay protection)
    const noncesCollection = db.collection<NonceDocument>(Collections.NONCES);
    const existingNonce = await noncesCollection.findOne({ nonce: message.nonce });

    if (existingNonce) {
      // Log replay attack attempt
      await db.collection(Collections.LOGS).insertOne({
        type: 'replay_detected',
        userId: message.initiatorId,
        details: `Duplicate nonce detected in key exchange init. SessionId: ${message.sessionId}`,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: 'Nonce already used (replay attack detected)',
        } as InitiateKeyExchangeResponse,
        { status: 400 }
      );
    }

    // Store nonce with TTL
    const nonceExpiresAt = new Date();
    nonceExpiresAt.setHours(nonceExpiresAt.getHours() + KEY_EXCHANGE_CONFIG.NONCE_TTL_HOURS);

    await noncesCollection.insertOne({
      nonce: message.nonce,
      userId: message.initiatorId,
      sessionId: message.sessionId,
      createdAt: new Date(),
      expiresAt: nonceExpiresAt,
    } as NonceDocument);

    // Store key exchange session
    const keyExchangeDoc: KeyExchangeDocument = {
      sessionId: message.sessionId,
      userId1: message.initiatorId,
      userId2: message.responderId,
      status: 'initiated',
      initMessage: {
        ephemeralPublicKey: message.ephemeralPublicKey,
        nonce: message.nonce,
        timestamp: new Date(message.timestamp),
        signature: message.signature,
      },
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    await keyExchangesCollection.insertOne(keyExchangeDoc as any);

    // Log successful initiation
    await db.collection(Collections.LOGS).insertOne({
      type: 'key_exchange',
      userId: message.initiatorId,
      details: `Key exchange initiated with user ${message.responderId}. SessionId: ${message.sessionId}`,
      timestamp: new Date(),
      success: true,
    });

    console.log('✅ Key exchange initiated:', message.sessionId);

    return NextResponse.json({
      success: true,
      message: 'Key exchange initiated successfully',
      sessionId: message.sessionId,
    } as InitiateKeyExchangeResponse);
  } catch (error: any) {
    console.error('❌ Key exchange initiation error:', error);

    return NextResponse.json(
      {
        success: false,
        message: error.message || 'Failed to initiate key exchange',
      } as InitiateKeyExchangeResponse,
      { status: 500 }
    );
  }
}
