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

    return NextResponse.json({
      success: true,
      status: session.status,
      createdAt: session.createdAt,
      updatedAt: session.updatedAt,
      completedAt: session.completedAt,
    } as KeyExchangeStatusResponse);
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
