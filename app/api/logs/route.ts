/**
 * GET /api/logs
 * Retrieve security logs with filtering
 */

import { NextRequest, NextResponse } from 'next/server';
import { connectToDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const type = searchParams.get('type');
    const userId = searchParams.get('userId');
    const limit = parseInt(searchParams.get('limit') || '100');
    const offset = parseInt(searchParams.get('offset') || '0');

    const { db } = await connectToDatabase();
    const logsCollection = db.collection(Collections.LOGS);

    // Build query
    const query: any = {};
    if (type) query.type = type;
    if (userId) query.userId = userId;

    // Fetch logs
    const logs = await logsCollection
      .find(query)
      .sort({ timestamp: -1 })
      .skip(offset)
      .limit(limit)
      .toArray();

    const total = await logsCollection.countDocuments(query);

    return NextResponse.json({
      success: true,
      logs,
      total,
      limit,
      offset,
    });
  } catch (error: any) {
    console.error('Error fetching logs:', error);
    return NextResponse.json(
      { success: false, message: 'Failed to fetch logs' },
      { status: 500 }
    );
  }
}
