/**
 * GET /api/key-exchange/status/:sessionId
 *
 * Retrieves the current status of a key exchange session
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db/connection';
import { Collections, type KeyExchangeDocument } from '@/lib/db/models';
import type { KeyExchangeStatusResponse } from '@/types';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ sessionId: string }> }
) {
  try {
    const { sessionId } = await params;

    if (!sessionId) {
      return NextResponse.json(
        {
          success: false,
          status: 'failed',
          createdAt: new Date(),
          updatedAt: new Date(),
        } as KeyExchangeStatusResponse,
        { status: 400 }
      );
    }

    // Connect to database
    const { db } = await connectToDatabase();

    // Find key exchange session
    const keyExchangesCollection = db.collection<KeyExchangeDocument>(Collections.KEY_EXCHANGES);
    const session = await keyExchangesCollection.findOne({ sessionId });

    if (!session) {
      return NextResponse.json(
        {
          success: false,
          status: 'failed',
          createdAt: new Date(),
          updatedAt: new Date(),
        } as KeyExchangeStatusResponse,
        { status: 404 }
      );
    }

    console.log(`✅ Retrieved status for key exchange session: ${sessionId} - ${session.status}`);

    // Include response message if status is 'responded' (for initiator to complete exchange)
    const responseData: any = {
      success: true,
      status: session.status,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
      completedAt: session.completedAt,
    };

    // If responded, include the response message for the initiator
    if (session.status === 'responded' && session.responseMessage) {
      responseData.responseMessage = {
        messageType: 'KEY_EXCHANGE_RESPONSE',
        sessionId: session.sessionId,
        responderId: session.userId2,
        initiatorId: session.userId1,
        ephemeralPublicKey: session.responseMessage.ephemeralPublicKey,
        nonce: session.responseMessage.nonce,
        initiatorNonce: session.initMessage?.nonce,
        timestamp: new Date(session.responseMessage.timestamp).getTime(),
        signature: session.responseMessage.signature,
      };
    }

    // If confirmed, include the confirm message for the responder
    if (session.status === 'confirmed' && session.confirmMessage) {
      responseData.confirmMessage = session.confirmMessage;
      // Also include responseMessage for initiator if they're still polling
      if (session.responseMessage) {
        responseData.responseMessage = {
          messageType: 'KEY_EXCHANGE_RESPONSE',
          sessionId: session.sessionId,
          responderId: session.userId2,
          initiatorId: session.userId1,
          ephemeralPublicKey: session.responseMessage.ephemeralPublicKey,
          nonce: session.responseMessage.nonce,
          initiatorNonce: session.initMessage?.nonce,
          timestamp: new Date(session.responseMessage.timestamp).getTime(),
          signature: session.responseMessage.signature,
        };
      }
    }

    return NextResponse.json(responseData);
  } catch (error: any) {
    console.error('❌ Error retrieving key exchange status:', error);

    return NextResponse.json(
      {
        success: false,
        status: 'failed',
        createdAt: new Date(),
        updatedAt: new Date(),
      } as KeyExchangeStatusResponse,
      { status: 500 }
    );
  }
}
