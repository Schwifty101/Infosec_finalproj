/**
 * Conversation List Component
 *
 * WhatsApp-style sidebar showing all conversations
 * Features:
 * - List of conversations sorted by most recent
 * - Last message preview (decrypted client-side)
 * - Unread count badges
 * - Timestamps
 * - Online/offline indicators
 */

'use client';

import { useState, useEffect } from 'react';
import { decryptMessage } from '@/lib/crypto/messaging-client';
import { getSessionKey } from '@/lib/crypto/sessionKeys';
import { getConversationId } from '@/lib/crypto/keyExchange';

interface Conversation {
  conversationId: string;
  peerUserId: string;
  peerUsername: string;
  lastMessage: {
    _id: string;
    senderId: string;
    receiverId: string;
    ciphertext: string;
    iv: string;
    authTag: string;
    nonce: string;
    sequenceNumber: number;
    timestamp: Date;
    delivered: boolean;
    read: boolean;
  };
  unreadCount: number;
  messageCount: number;
}

interface Props {
  currentUserId: string;
  currentUsername: string;
  selectedConversationId: string | null;
  onSelectConversation: (conversation: Conversation) => void;
}

export default function ConversationList({
  currentUserId,
  currentUsername,
  selectedConversationId,
  onSelectConversation,
}: Props) {
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [decryptedPreviews, setDecryptedPreviews] = useState<Record<string, string>>({});

  useEffect(() => {
    fetchConversations();

    // Poll for updates every 10 seconds
    const interval = setInterval(fetchConversations, 10000);

    return () => clearInterval(interval);
  }, [currentUserId]);

  useEffect(() => {
    // Decrypt last message previews
    conversations.forEach(async (conv) => {
      if (decryptedPreviews[conv.conversationId]) return;

      try {
        const conversationId = getConversationId(conv.peerUserId, currentUserId);
        const sessionKey = await getSessionKey(conversationId);

        if (sessionKey) {
          const decrypted = await decryptMessage(
            conv.lastMessage.ciphertext,
            conv.lastMessage.iv,
            conv.lastMessage.authTag,
            conv.lastMessage.nonce,
            conv.lastMessage.sequenceNumber,
            sessionKey
          );

          setDecryptedPreviews((prev) => ({
            ...prev,
            [conv.conversationId]: decrypted,
          }));
        }
      } catch (err) {
        // Silently fail, show encrypted placeholder
        setDecryptedPreviews((prev) => ({
          ...prev,
          [conv.conversationId]: '[Encrypted message]',
        }));
      }
    });
  }, [conversations]);

  const fetchConversations = async () => {
    try {
      const response = await fetch(
        `/api/conversations?userId=${currentUserId}`,
        {
          headers: {
            'x-user-id': currentUserId,
          },
        }
      );

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Failed to load conversations');
      }

      setConversations(data.conversations);
      setError('');
    } catch (err: any) {
      console.error('Failed to load conversations:', err);
      setError(err.message || 'Failed to load conversations');
    } finally {
      setLoading(false);
    }
  };

  const formatTimestamp = (timestamp: Date) => {
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now.getTime() - date.getTime();

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

  const truncateText = (text: string, maxLength: number = 40) => {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength) + '...';
  };

  if (loading) {
    return (
      <div
        style={{
          width: '320px',
          borderRight: '1px solid #dee2e6',
          backgroundColor: 'white',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '2rem',
        }}
      >
        <div style={{ textAlign: 'center', color: '#6c757d' }}>
          <div
            style={{
              width: '32px',
              height: '32px',
              border: '3px solid #e9ecef',
              borderTop: '3px solid #007bff',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
              margin: '0 auto 1rem',
            }}
          />
          Loading conversations...
          <style jsx>{`
            @keyframes spin {
              0% {
                transform: rotate(0deg);
              }
              100% {
                transform: rotate(360deg);
              }
            }
          `}</style>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        width: '320px',
        borderRight: '1px solid #dee2e6',
        backgroundColor: 'white',
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '1rem 1.5rem',
          borderBottom: '1px solid #dee2e6',
          backgroundColor: '#f8f9fa',
        }}
      >
        <h2 style={{ margin: 0, fontSize: '1.3rem' }}>Messages</h2>
        <div style={{ fontSize: '0.85rem', color: '#6c757d', marginTop: '0.25rem' }}>
          {currentUsername}
        </div>
      </div>

      {/* Conversations */}
      <div style={{ flex: 1, overflowY: 'auto' }}>
        {error && (
          <div
            style={{
              padding: '1rem',
              margin: '1rem',
              backgroundColor: '#fee',
              color: '#dc3545',
              borderRadius: '4px',
              fontSize: '0.9rem',
            }}
          >
            {error}
          </div>
        )}

        {conversations.length === 0 && !error && (
          <div
            style={{
              padding: '3rem 2rem',
              textAlign: 'center',
              color: '#6c757d',
            }}
          >
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>💬</div>
            <div style={{ fontSize: '1rem', marginBottom: '0.5rem' }}>
              No conversations yet
            </div>
            <div style={{ fontSize: '0.85rem', opacity: 0.7 }}>
              Start chatting by initiating a key exchange with another user
            </div>
          </div>
        )}

        {conversations.map((conv) => {
          const isSelected = conv.conversationId === selectedConversationId;
          const preview = decryptedPreviews[conv.conversationId] || 'Loading...';
          const isSent = conv.lastMessage.senderId === currentUserId;

          return (
            <div
              key={conv.conversationId}
              onClick={() => onSelectConversation(conv)}
              style={{
                padding: '0.75rem 1rem',
                borderBottom: '1px solid #f0f0f0',
                cursor: 'pointer',
                backgroundColor: isSelected ? '#e7f3ff' : 'white',
                transition: 'background-color 0.2s',
              }}
              onMouseEnter={(e) => {
                if (!isSelected) {
                  e.currentTarget.style.backgroundColor = '#f8f9fa';
                }
              }}
              onMouseLeave={(e) => {
                if (!isSelected) {
                  e.currentTarget.style.backgroundColor = 'white';
                }
              }}
            >
              {/* Top row: Username and timestamp */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.4rem',
                }}
              >
                <div
                  style={{
                    fontWeight: conv.unreadCount > 0 ? 'bold' : 'normal',
                    fontSize: '1rem',
                    color: '#212529',
                  }}
                >
                  {conv.peerUsername}
                </div>
                <div
                  style={{
                    fontSize: '0.75rem',
                    color: '#6c757d',
                  }}
                >
                  {formatTimestamp(conv.lastMessage.timestamp)}
                </div>
              </div>

              {/* Bottom row: Preview and unread badge */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div
                  style={{
                    fontSize: '0.9rem',
                    color: '#6c757d',
                    flex: 1,
                    marginRight: '0.5rem',
                  }}
                >
                  <span style={{ marginRight: '0.25rem' }}>
                    {isSent && '✓'}
                  </span>
                  {truncateText(preview)}
                </div>

                {conv.unreadCount > 0 && (
                  <div
                    style={{
                      backgroundColor: '#007bff',
                      color: 'white',
                      borderRadius: '10px',
                      padding: '0.2rem 0.5rem',
                      fontSize: '0.75rem',
                      fontWeight: 'bold',
                      minWidth: '20px',
                      textAlign: 'center',
                    }}
                  >
                    {conv.unreadCount}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
