/**
 * GET /api/messages/sequence/[conversationId]
 *
 * Returns the next sequence number for a conversation
 * Used by client-side encryption before sending a message
 */

import { NextRequest, NextResponse } from 'next/server';
import { getNextSequenceNumber } from '@/lib/crypto/messaging-server';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ conversationId: string }> }
) {
  try {
    const { conversationId } = await params;

    if (!conversationId) {
      return NextResponse.json(
        { success: false, message: 'Conversation ID is required' },
        { status: 400 }
      );
    }

    // Get senderId from query params (CRITICAL for per-sender sequence tracking)
    const { searchParams } = new URL(request.url);
    const senderId = searchParams.get('senderId');

    if (!senderId) {
      return NextResponse.json(
        { success: false, message: 'Sender ID is required' },
        { status: 400 }
      );
    }

    const nextSequenceNumber = await getNextSequenceNumber(conversationId, senderId);

    console.log(`📊 Sequence query: conversationId=${conversationId}, senderId=${senderId}, nextSequenceNumber=${nextSequenceNumber}`);

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
