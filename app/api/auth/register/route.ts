import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getDatabase } from '@/lib/db/connection';
import { Collections, UserDocument } from '@/lib/db/models';

/**
 * POST /api/auth/register
 * Register a new user with username and password
 *
 * Body: { username: string, password: string }
 * Returns: { success: boolean, userId?: string, message: string }
 */
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { username, password } = body;

    // Validate input
    if (!username || !password) {
      return NextResponse.json(
        { success: false, message: 'Username and password are required' },
        { status: 400 }
      );
    }

    // Validate username format (alphanumeric, 3-20 chars)
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return NextResponse.json(
        { success: false, message: 'Username must be 3-20 alphanumeric characters' },
        { status: 400 }
      );
    }

    // Validate password strength (min 8 chars)
    if (password.length < 8) {
      return NextResponse.json(
        { success: false, message: 'Password must be at least 8 characters' },
        { status: 400 }
      );
    }

    // Connect to database
    const db = await getDatabase();
    const usersCollection = db.collection<UserDocument>(Collections.USERS);

    // Check if username already exists
    const existingUser = await usersCollection.findOne({ username });
    if (existingUser) {
      return NextResponse.json(
        { success: false, message: 'Username already exists' },
        { status: 409 }
      );
    }

    // Hash password with bcrypt (10 rounds)
    const passwordHash = await bcrypt.hash(password, 10);

    // Create new user document
    const newUser: UserDocument = {
      username,
      passwordHash,
      createdAt: new Date(),
    };

    // Insert user into database
    const result = await usersCollection.insertOne(newUser as any);

    // Log successful registration
    await db.collection(Collections.LOGS).insertOne({
      type: 'auth',
      userId: result.insertedId.toString(),
      details: `User registered: ${username}`,
      timestamp: new Date(),
      ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
      success: true,
    });

    return NextResponse.json(
      {
        success: true,
        userId: result.insertedId.toString(),
        message: 'User registered successfully',
      },
      { status: 201 }
    );

  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
