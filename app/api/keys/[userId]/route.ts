import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import { ObjectId } from 'mongodb';

/**
 * GET /api/keys/[userId]
 * Retrieve public key for specific user
 *
 * Params: { userId: string }
 * Returns: { success: boolean, publicKey?: string, username?: string, message: string }
 */
export async function GET(
  request: NextRequest,
  { params }: { params: { userId: string } }
) {
  try {
    const { userId } = params;

    if (!userId) {
      return NextResponse.json(
        { success: false, message: 'userId parameter is required' },
        { status: 400 }
      );
    }

    // Validate ObjectId format
    if (!ObjectId.isValid(userId)) {
      return NextResponse.json(
        { success: false, message: 'Invalid userId format' },
        { status: 400 }
      );
    }

    // Connect to database
    const db = await getDatabase();
    const usersCollection = db.collection(Collections.USERS);

    // Find user and retrieve public key
    const user = await usersCollection.findOne(
      { _id: new ObjectId(userId) },
      { projection: { publicKey: 1, username: 1 } }
    );

    if (!user) {
      return NextResponse.json(
        { success: false, message: 'User not found' },
        { status: 404 }
      );
    }

    if (!user.publicKey) {
      return NextResponse.json(
        { success: false, message: 'Public key not available for this user' },
        { status: 404 }
      );
    }

    // Log public key retrieval
    await db.collection(Collections.LOGS).insertOne({
      type: 'metadata_access',
      userId,
      details: `Public key retrieved for user: ${user.username}`,
      timestamp: new Date(),
      ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
    });

    return NextResponse.json(
      {
        success: true,
        publicKey: user.publicKey,
        username: user.username,
        message: 'Public key retrieved successfully',
      },
      { status: 200 }
    );

  } catch (error) {
    console.error('Public key retrieval error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
