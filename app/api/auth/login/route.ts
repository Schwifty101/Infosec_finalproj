import { NextRequest, NextResponse } from 'next/server';
import bcrypt from 'bcryptjs';
import { getDatabase } from '@/lib/db/connection';
import { Collections, UserDocument } from '@/lib/db/models';

/**
 * POST /api/auth/login
 * Authenticate user with username and password
 *
 * Body: { username: string, password: string }
 * Returns: { success: boolean, userId?: string, username?: string, publicKey?: string, message: string }
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

    // Connect to database
    const db = await getDatabase();
    const usersCollection = db.collection<UserDocument>(Collections.USERS);

    // Find user by username
    const user = await usersCollection.findOne({ username });
    if (!user) {
      // Log failed login attempt
      await db.collection(Collections.LOGS).insertOne({
        type: 'auth',
        details: `Failed login attempt: username not found - ${username}`,
        timestamp: new Date(),
        ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
        success: false,
      });

      return NextResponse.json(
        { success: false, message: 'Invalid username or password' },
        { status: 401 }
      );
    }

    // Compare password with hash
    const passwordMatch = await bcrypt.compare(password, user.passwordHash);
    if (!passwordMatch) {
      // Log failed login attempt
      await db.collection(Collections.LOGS).insertOne({
        type: 'auth',
        userId: (user as any)._id.toString(),
        details: `Failed login attempt: incorrect password - ${username}`,
        timestamp: new Date(),
        ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
        success: false,
      });

      return NextResponse.json(
        { success: false, message: 'Invalid username or password' },
        { status: 401 }
      );
    }

    // Log successful login
    await db.collection(Collections.LOGS).insertOne({
      type: 'auth',
      userId: (user as any)._id.toString(),
      details: `Successful login: ${username}`,
      timestamp: new Date(),
      ipAddress: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown',
      success: true,
    });

    // Return user info (including public key if available)
    return NextResponse.json(
      {
        success: true,
        userId: (user as any)._id.toString(),
        username: user.username,
        publicKey: user.publicKey || null,
        message: 'Login successful',
      },
      { status: 200 }
    );

  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { success: false, message: 'Internal server error' },
      { status: 500 }
    );
  }
}
