/**
 * GET /api/files/download/[fileId]
 *
 * Retrieves encrypted file from MongoDB
 * Validates user authorization (must be sender or receiver)
 * Logs access attempts
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import { ObjectId } from 'mongodb';

export async function GET(
  request: NextRequest,
  { params }: { params: { fileId: string } }
) {
  try {
    const { fileId } = params;

    // Validate fileId format
    if (!ObjectId.isValid(fileId)) {
      return NextResponse.json(
        { success: false, message: 'Invalid file ID' },
        { status: 400 }
      );
    }

    // Get current user ID from header
    // In production, this would come from authenticated session
    const currentUserId = request.headers.get('X-User-Id');
    if (!currentUserId) {
      return NextResponse.json(
        { success: false, message: 'Unauthorized: No user ID provided' },
        { status: 401 }
      );
    }

    const db = await getDatabase();
    const filesCollection = db.collection(Collections.FILES);
    const logsCollection = db.collection(Collections.LOGS);

    // Fetch file from database
    const file = await filesCollection.findOne({ _id: new ObjectId(fileId) });

    if (!file) {
      return NextResponse.json(
        { success: false, message: 'File not found' },
        { status: 404 }
      );
    }

    // Authorization check: User must be sender or receiver
    if (file.senderId !== currentUserId && file.receiverId !== currentUserId) {
      console.warn(
        `⚠️ Unauthorized file access attempt by ${currentUserId} on file ${fileId}`
      );

      // Log unauthorized access attempt
      await logsCollection.insertOne({
        type: 'unauthorized_access',
        userId: currentUserId,
        details: `Unauthorized file download attempt: ${fileId}`,
        fileId,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        { success: false, message: 'Access denied: Not authorized for this file' },
        { status: 403 }
      );
    }

    // Log successful file access
    await logsCollection.insertOne({
      type: 'file_downloaded',
      userId: currentUserId,
      details: `File accessed: ${file.filename}`,
      fileId,
      timestamp: new Date(),
      success: true,
    });

    console.log(
      `✅ File ${fileId} accessed by ${currentUserId} (${file.filename})`
    );

    // Return encrypted file + metadata for client-side decryption
    return NextResponse.json(
      {
        success: true,
        file: {
          _id: fileId,
          ciphertext: file.ciphertext,
          iv: file.iv,
          authTag: file.authTag,
          nonce: file.nonce,
          filename: file.filename,
          mimeType: file.mimeType,
          size: file.size,
          senderId: file.senderId,
          receiverId: file.receiverId,
          uploadedAt: file.uploadedAt,
        },
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('❌ File download error:', error);

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to download file',
        error: error.message,
      },
      { status: 500 }
    );
  }
}
