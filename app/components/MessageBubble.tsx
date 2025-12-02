/**
 * Message Bubble Component
 *
 * Displays individual message with client-side decryption
 * Shows sent/received styling, timestamps, and delivery status
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import { decryptMessage } from '@/lib/crypto/messaging-client';
import { getSessionKey } from '@/lib/crypto/sessionKeys';
import { getConversationId } from '@/lib/crypto/keyExchange';

interface Message {
  _id: string;
  senderId: string;
  receiverId: string;
  ciphertext: string;
  iv: string;
  authTag: string;
  nonce: string;
  sequenceNumber: number;
  timestamp: Date;
  delivered?: boolean;
  read?: boolean;
}

interface Props {
  message: Message;
  currentUserId: string;
  peerUserId: string;
}

export default function MessageBubble({ message, currentUserId, peerUserId }: Props) {
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [decrypting, setDecrypting] = useState(true);
  const [error, setError] = useState(false);

  const isSent = message.senderId === currentUserId;

  const decryptAndDisplay = useCallback(async () => {
    try {
      setDecrypting(true);
      setError(false);

      // Get conversation ID
      const conversationId = getConversationId(currentUserId, peerUserId);

      // Get session key
      const sessionKey = await getSessionKey(conversationId);

      if (!sessionKey) {
        console.warn('No session key found for conversation');
        setPlaintext('[Unable to decrypt: No session key]');
        setError(true);
        setDecrypting(false);
        return;
      }

      // Decrypt message
      const decrypted = await decryptMessage(
        message.ciphertext,
        message.iv,
        message.authTag,
        message.nonce,
        message.sequenceNumber,
        sessionKey
      );

      setPlaintext(decrypted);
      setDecrypting(false);
    } catch (err: any) {
      console.error('Message decryption failed:', err);
      // More helpful error message explaining potential causes
      setPlaintext('[🔒 Unable to decrypt - Session key may have changed]');
      setError(true);
      setDecrypting(false);

      // Log security event (don't await - fire and forget)
      fetch('/api/security/log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: 'decrypt_fail',
          messageId: message._id,
          details: 'Message decryption failed - possible key rotation or tampering',
          timestamp: new Date(),
        }),
      }).catch(() => {
        // Non-fatal - ignore errors
      });
    }
  }, [message, currentUserId, peerUserId]);

  useEffect(() => {
    decryptAndDisplay();
  }, [decryptAndDisplay]);

  const formatTimestamp = (timestamp: Date) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

    // Less than 1 minute
    if (diff < 60000) {
      return 'Just now';
    }

    // Less than 1 hour
    if (diff < 3600000) {
      const minutes = Math.floor(diff / 60000);
      return `${minutes}m ago`;
    }

    // Today
    if (date.toDateString() === now.toDateString()) {
      return date.toLocaleTimeString('en-US', {
        hour: 'numeric',
        minute: '2-digit',
        hour12: true,
      });
    }

    // Yesterday
    const yesterday = new Date(now);
    yesterday.setDate(yesterday.getDate() - 1);
    if (date.toDateString() === yesterday.toDateString()) {
      return 'Yesterday';
    }

    // This week
    if (diff < 7 * 24 * 60 * 60 * 1000) {
      return date.toLocaleDateString('en-US', { weekday: 'short' });
    }

    // Older
    return date.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: isSent ? 'flex-end' : 'flex-start',
        marginBottom: '0.75rem',
        padding: '0 1rem',
      }}
    >
      <div
        style={{
          maxWidth: '70%',
          padding: '0.75rem 1rem',
          borderRadius: '12px',
          backgroundColor: isSent ? '#007bff' : '#e9ecef',
          color: isSent ? 'white' : '#212529',
          wordBreak: 'break-word',
          boxShadow: '0 1px 2px rgba(0,0,0,0.1)',
        }}
      >
        {/* Message content */}
        <div style={{ marginBottom: '0.25rem', fontSize: '0.95rem' }}>
          {decrypting ? (
            <span style={{ fontStyle: 'italic', opacity: 0.7 }}>
              Decrypting...
            </span>
          ) : error ? (
            <span style={{ fontStyle: 'italic', color: isSent ? '#ffcccc' : '#dc3545' }}>
              {plaintext}
            </span>
          ) : (
            plaintext
          )}
        </div>

        {/* Metadata row */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: '0.5rem',
            fontSize: '0.75rem',
            opacity: 0.8,
            marginTop: '0.25rem',
          }}
        >
          {/* Timestamp */}
          <span>{formatTimestamp(message.timestamp)}</span>

          {/* Delivery status (only for sent messages) */}
          {isSent && (
            <span>
              {message.read ? (
                <span style={{ color: '#90cdf4' }}>✓✓</span>
              ) : message.delivered ? (
                <span>✓✓</span>
              ) : (
                <span>✓</span>
              )}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}
