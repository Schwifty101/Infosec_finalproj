/**
 * GET /api/messages/sequence/[conversationId]
 *
 * Returns the next sequence number for a conversation
 * Used by client-side encryption before sending a message
 */

import { NextRequest, NextResponse } from 'next/server';
import { getNextSequenceNumber } from '@/lib/crypto/messaging-server';

interface RouteParams {
  params: {
    conversationId: string;
  };
}

export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { conversationId } = params;

    if (!conversationId) {
      return NextResponse.json(
        { success: false, message: 'Conversation ID is required' },
        { status: 400 }
      );
    }

    const nextSequenceNumber = await getNextSequenceNumber(conversationId);

    return NextResponse.json({
      success: true,
      nextSequenceNumber,
    });
  } catch (error) {
    console.error('Failed to get sequence number:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
