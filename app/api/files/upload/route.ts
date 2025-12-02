/**
 * POST /api/files/upload
 *
 * Stores encrypted file in MongoDB
 * Validates nonce uniqueness for replay protection
 * Enforces file size limits
 * Logs security events
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import { isNonceUsed, storeNonce } from '@/lib/crypto/messaging-server';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const {
      senderId,
      receiverId,
      ciphertext,
      iv,
      authTag,
      nonce,
      filename,
      mimeType,
      size,
    } = body;

    // Validate required fields
    if (
      !senderId ||
      !receiverId ||
      !ciphertext ||
      !iv ||
      !authTag ||
      !nonce ||
      !filename ||
      !mimeType ||
      size === undefined
    ) {
      return NextResponse.json(
        {
          success: false,
          message: 'Missing required fields',
        },
        { status: 400 }
      );
    }

    // Validate senderId and receiverId are different
    if (senderId === receiverId) {
      return NextResponse.json(
        {
          success: false,
          message: 'Cannot send file to yourself',
        },
        { status: 400 }
      );
    }

    // Validate file size (50MB encrypted data limit)
    // Base64 encoding increases size by ~33%, so ciphertext length check
    const FILE_SIZE_LIMIT = 50 * 1024 * 1024; // 50MB
    const estimatedSize = (ciphertext.length * 3) / 4; // Decode Base64 size estimate

    if (estimatedSize > FILE_SIZE_LIMIT) {
      return NextResponse.json(
        {
          success: false,
          message: 'File exceeds 50MB limit',
        },
        { status: 400 }
      );
    }

    const db = await getDatabase();
    const filesCollection = db.collection(Collections.FILES);
    const logsCollection = db.collection(Collections.LOGS);

    // Check nonce uniqueness (replay protection)
    const nonceExists = await isNonceUsed(nonce);
    if (nonceExists) {
      console.warn(
        `⚠️ Replay attack detected: Duplicate file nonce from ${senderId}`
      );

      // Log security event
      await logsCollection.insertOne({
        type: 'replay_detected',
        userId: senderId,
        details: `Duplicate nonce detected in file upload: ${filename}`,
        nonce,
        timestamp: new Date(),
        success: false,
      });

      return NextResponse.json(
        {
          success: false,
          message: 'Replay attack detected: Duplicate nonce',
        },
        { status: 400 }
      );
    }

    // Insert file into database
    const result = await filesCollection.insertOne({
      senderId,
      receiverId,
      ciphertext,
      iv,
      authTag,
      nonce,
      filename,
      mimeType,
      size,
      uploadedAt: new Date(),
      delivered: false,
      deliveredAt: null,
    });

    const fileId = result.insertedId.toString();

    // Store nonce for replay protection
    await storeNonce(nonce, senderId, fileId);

    // Log successful file upload
    await logsCollection.insertOne({
      type: 'file_uploaded',
      userId: senderId,
      details: `Encrypted file uploaded: ${filename} (${size} bytes)`,
      fileId,
      timestamp: new Date(),
      success: true,
    });

    console.log(
      `✅ File ${fileId} uploaded: ${senderId} -> ${receiverId} (${filename}, ${size} bytes)`
    );

    return NextResponse.json(
      {
        success: true,
        fileId,
        timestamp: new Date().toISOString(),
      },
      { status: 200 }
    );
  } catch (error: any) {
    console.error('❌ File upload error:', error);

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to upload file',
        error: error.message,
      },
      { status: 500 }
    );
  }
}
