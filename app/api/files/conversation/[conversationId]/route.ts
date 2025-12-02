/**
 * GET /api/files/conversation/[conversationId]
 *
 * Lists all encrypted files in a conversation
 * Returns files in chronological order with pagination support
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ conversationId: string }> }
) {
  try {
    const { conversationId } = await params;

    // Parse conversationId to get user IDs
    const userIds = conversationId.split('_').sort();
    if (userIds.length !== 2) {
      return NextResponse.json(
        { success: false, message: 'Invalid conversation ID' },
        { status: 400 }
      );
    }

    const [userId1, userId2] = userIds;

    // Optional pagination parameters
    const { searchParams } = new URL(request.url);
    const limit = parseInt(searchParams.get('limit') || '50', 10);
    const offset = parseInt(searchParams.get('offset') || '0', 10);

    const db = await getDatabase();
    const filesCollection = db.collection(Collections.FILES);

    // Query files in this conversation
    const query = {
      $or: [
        { senderId: userId1, receiverId: userId2 },
        { senderId: userId2, receiverId: userId1 },
      ],
    };

    // Get total count
    const totalCount = await filesCollection.countDocuments(query);

    // Get files with pagination
    const files = await filesCollection
      .find(query)
      .sort({ uploadedAt: -1 }) // Newest first
      .skip(offset)
      .limit(limit)
      .toArray();

    // Map to response format (include only necessary fields)
    const fileList = files.map((file) => ({
      _id: file._id.toString(),
      filename: file.filename,
      mimeType: file.mimeType,
      size: file.size,
      senderId: file.senderId,
      receiverId: file.receiverId,
      uploadedAt: file.uploadedAt,
      delivered: file.delivered,
    }));

    console.log(
      `✅ Retrieved ${files.length} files from conversation ${conversationId}`
    );

    return NextResponse.json(
      {
        success: true,
        files: fileList,
        count: files.length,
        total: totalCount,
        hasMore: offset + files.length < totalCount,
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('❌ File conversation listing error:', error);

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to retrieve files',
        error: error.message,
      },
      { status: 500 }
    );
  }
}
