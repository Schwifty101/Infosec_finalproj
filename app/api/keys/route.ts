import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';
import { ObjectId } from 'mongodb';

/**
 * POST /api/keys
 * Store public key for authenticated user
 *
 * Body: { userId: string, publicKey: string }
 * Returns: { success: boolean, message: string }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { userId, publicKey } = body;

    // Validate input
    if (!userId || !publicKey) {
      return NextResponse.json(
        { success: false, message: 'userId and publicKey are required' },
        { status: 400 }
      );
    }

    // Validate public key format (basic check for JWK structure)
    try {
      const parsedKey = JSON.parse(publicKey);
      if (!parsedKey.kty || !parsedKey.crv || !parsedKey.x || !parsedKey.y) {
        throw new Error('Invalid JWK format');
      }
    } catch (error) {
      return NextResponse.json(
        { success: false, message: 'Invalid public key format' },
        { status: 400 }
      );
    }

    // Connect to database
    const db = await getDatabase();
    const usersCollection = db.collection(Collections.USERS);

    // Update user document with public key
    const result = await usersCollection.updateOne(
      { _id: new ObjectId(userId) },
      { $set: { publicKey } }
    );

    if (result.matchedCount === 0) {
      return NextResponse.json(
        { success: false, message: 'User not found' },
        { status: 404 }
      );
    }

    // Log public key storage
    await db.collection(Collections.LOGS).insertOne({
      type: 'metadata_access',
      userId,
      details: 'Public key stored',
      timestamp: new Date(),
      ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
    });

    return NextResponse.json(
      {
        success: true,
        message: 'Public key stored successfully',
      },
      { status: 200 }
    );

  } catch (error) {
    console.error('Public key storage error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
