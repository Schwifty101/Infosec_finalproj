/**
 * POST /api/security/log
 *
 * Logs security events from client-side (e.g., decryption failures)
 * Used for monitoring and audit purposes
 */

import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db/connection';
import { Collections } from '@/lib/db/models';

export async function POST(request: NextRequest) {
    try {
        const body = await request.json();
        const { type, messageId, details, timestamp, userId, conversationId } = body;

        // Validate required fields
        if (!type || !details) {
            return NextResponse.json(
                { success: false, message: 'Missing required fields' },
                { status: 400 }
            );
        }

        const db = await getDatabase();
        const logsCollection = db.collection(Collections.LOGS);

        // Insert security log
        await logsCollection.insertOne({
            type: type,
            messageId: messageId || null,
            userId: userId || null,
            conversationId: conversationId || null,
            details: details,
            timestamp: timestamp ? new Date(timestamp) : new Date(),
            ipAddress:
                request.headers.get('x-forwarded-for') ||
                request.headers.get('x-real-ip') ||
                'unknown',
            userAgent: request.headers.get('user-agent') || 'unknown',
            success: false, // Security logs are typically for failures
        });

        console.log(`🔒 Security event logged: ${type} - ${details}`);

        return NextResponse.json(
            { success: true, message: 'Security event logged' },
            { status: 200 }
        );
    } catch (error: any) {
        console.error('❌ Security log error:', error);

        // Don't fail silently - log to console at minimum
        return NextResponse.json(
            { success: false, message: 'Failed to log security event' },
            { status: 500 }
        );
    }
}
