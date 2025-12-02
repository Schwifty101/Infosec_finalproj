import { NextRequest, NextResponse } from 'next/server';
import { connectDB } from '@/lib/db/mongodb';
import { User } from '@/lib/db/models';
import { ObjectId } from 'mongodb';

/**
 * User Search API Endpoint
 *
 * Purpose: Instagram-style username search for discovering users
 * Method: GET
 * Query Params:
 *   - q: Search query (username substring)
 *   - currentUserId: Current user ID (to exclude self from results)
 *
 * Returns: Array of matching users (max 20)
 */
export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const query = searchParams.get('q');
    const currentUserId = searchParams.get('currentUserId');

    // Validation
    if (!query || query.length < 1) {
      return NextResponse.json(
        {
          success: false,
          message: 'Search query must be at least 1 character'
        },
        { status: 400 }
      );
    }

    if (!currentUserId) {
      return NextResponse.json(
        { success: false, message: 'Current user ID is required' },
        { status: 400 }
      );
    }

    // Connect to database
    const db = await connectDB();

    // Validate current user exists
    const currentUser = await db.collection('users').findOne({
      _id: new ObjectId(currentUserId)
    });

    if (!currentUser) {
      return NextResponse.json(
        { success: false, message: 'Invalid user ID' },
        { status: 401 }
      );
    }

    // Search for users (case-insensitive, exclude self, limit 20)
    const users = await db
      .collection('users')
      .find({
        username: { $regex: query, $options: 'i' },
        _id: { $ne: new ObjectId(currentUserId) }
      })
      .project({
        username: 1,
        publicKey: 1
      })
      .limit(20)
      .toArray();

    // Format response
    const formattedUsers = users.map(user => ({
      _id: user._id.toString(),
      username: user.username,
      hasPublicKey: !!user.publicKey
    }));

    // Security logging
    await db.collection('security_logs').insertOne({
      type: 'user_search',
      userId: currentUserId,
      username: currentUser.username,
      details: {
        searchQuery: query,
        resultsCount: formattedUsers.length,
        ip: request.headers.get('x-forwarded-for') ||
            request.headers.get('x-real-ip') ||
            'unknown'
      },
      timestamp: new Date(),
      success: true
    });

    return NextResponse.json({
      success: true,
      users: formattedUsers,
      count: formattedUsers.length
    });

  } catch (error) {
    console.error('User search error:', error);

    // Log security error
    try {
      const db = await connectDB();
      await db.collection('security_logs').insertOne({
        type: 'user_search_error',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error'
        },
        timestamp: new Date(),
        success: false
      });
    } catch (logError) {
      console.error('Failed to log security error:', logError);
    }

    return NextResponse.json(
      {
        success: false,
        message: 'Failed to search users',
        error: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}
