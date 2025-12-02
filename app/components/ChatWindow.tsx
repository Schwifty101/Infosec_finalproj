/**
 * Chat Window Component
 *
 * Main messaging container that orchestrates:
 * - Message display with MessageList
 * - Message input with MessageInput
 * - WebSocket message reception
 * - Message loading and pagination
 */

'use client';

import { useState, useEffect, useCallback } from 'react';
import { Socket } from 'socket.io-client';
import MessageList from './MessageList';
import MessageInput from './MessageInput';
import { useWebSocket } from '@/lib/hooks/useWebSocket';
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
  currentUserId: string;
  currentUsername: string;
  peerUserId: string;
  peerUsername: string;
}

export default function ChatWindow({
  currentUserId,
  currentUsername,
  peerUserId,
  peerUsername,
}: Props) {
  const [messages, setMessages] = useState<Message[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [hasMore, setHasMore] = useState(true);

  const { socket, connected } = useWebSocket(currentUserId);
  const conversationId = getConversationId(currentUserId, peerUserId);

  const loadMessages = useCallback(async (cursor?: string) => {
    try {
      setLoading(true);
      setError('');

      const url = cursor
        ? `/api/messages/conversation/${conversationId}?before=${cursor}&limit=50`
        : `/api/messages/conversation/${conversationId}?limit=50`;

      const response = await fetch(url);
      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Failed to load messages');
      }

      // Reverse messages (API returns newest first, we want oldest first for display)
      const reversedMessages = data.messages.reverse();

      if (cursor) {
        // Prepend older messages
        setMessages((prev) => [...reversedMessages, ...prev]);
      } else {
        // Initial load
        setMessages(reversedMessages);
      }

      setHasMore(data.hasMore);
      console.log(`✅ Loaded ${data.messages.length} messages`);
    } catch (err: any) {
      console.error('Failed to load messages:', err);
      setError(err.message || 'Failed to load messages');
    } finally {
      setLoading(false);
    }
  }, [conversationId]);

  // Load initial messages
  useEffect(() => {
    loadMessages();
  }, [loadMessages]);

  // Set up WebSocket listeners
  useEffect(() => {
    if (!socket) return;

    // Handle incoming messages
    const handleMessageReceive = (data: any) => {
      console.log('📥 Received message via WebSocket:', data);

      // Add to messages if it's for this conversation
      if (
        (data.senderId === peerUserId && data.receiverId === currentUserId) ||
        (data.senderId === currentUserId && data.receiverId === peerUserId)
      ) {
        setMessages((prev) => {
          // Avoid duplicates
          if (prev.some((msg) => msg._id === data._id)) {
            return prev;
          }
          return [...prev, data];
        });
      }
    };

    // Handle delivery confirmations
    const handleMessageDelivered = (data: { messageId: string; deliveredAt: number }) => {
      console.log('✓ Message delivered:', data.messageId);
      setMessages((prev) =>
        prev.map((msg) =>
          msg._id === data.messageId
            ? { ...msg, delivered: true, deliveredAt: new Date(data.deliveredAt) }
            : msg
        )
      );
    };

    // Handle read receipts
    const handleMessageRead = (data: {
      messageId: string;
      readBy: string;
      readAt: number;
    }) => {
      console.log('✓✓ Message read:', data.messageId);
      setMessages((prev) =>
        prev.map((msg) =>
          msg._id === data.messageId
            ? { ...msg, read: true, readAt: new Date(data.readAt) }
            : msg
        )
      );
    };

    socket.on('message:receive', handleMessageReceive);
    socket.on('message:delivered', handleMessageDelivered);
    socket.on('message:read', handleMessageRead);

    return () => {
      socket.off('message:receive', handleMessageReceive);
      socket.off('message:delivered', handleMessageDelivered);
      socket.off('message:read', handleMessageRead);
    };
  }, [socket, peerUserId, currentUserId]);

  const handleLoadMore = useCallback(
    async (cursor: string) => {
      if (!hasMore || loading) return;
      await loadMessages(cursor);
    },
    [hasMore, loading, loadMessages]
  );

  const handleMessageSent = (message: Message) => {
    // Add optimistically to UI
    setMessages((prev) => [...prev, message]);
  };

  if (loading && messages.length === 0) {
    return (
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
          backgroundColor: '#f8f9fa',
        }}
      >
        {/* Header */}
        <div
          style={{
            padding: '1rem 1.5rem',
            borderBottom: '1px solid #dee2e6',
            backgroundColor: 'white',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <h3 style={{ margin: 0, fontSize: '1.1rem' }}>{peerUsername}</h3>
            <div style={{ fontSize: '0.85rem', color: '#6c757d', marginTop: '0.25rem' }}>
              {connected ? '🟢 Online' : '⚫ Offline'}
            </div>
          </div>
        </div>

        {/* Loading state */}
        <div
          style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#6c757d',
          }}
        >
          <div style={{ textAlign: 'center' }}>
            <div
              style={{
                width: '40px',
                height: '40px',
                border: '4px solid #e9ecef',
                borderTop: '4px solid #007bff',
                borderRadius: '50%',
                animation: 'spin 1s linear infinite',
                margin: '0 auto 1rem',
              }}
            />
            Loading conversation...
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
      </div>
    );
  }

  if (error) {
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          height: '100%',
          color: '#dc3545',
          textAlign: 'center',
          padding: '2rem',
        }}
      >
        <div>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>⚠️</div>
          <div style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>
            Failed to load conversation
          </div>
          <div style={{ fontSize: '0.9rem', opacity: 0.7, marginBottom: '1rem' }}>
            {error}
          </div>
          <button
            onClick={() => loadMessages()}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: '100%',
        backgroundColor: '#f8f9fa',
      }}
    >
      {/* Header */}
      <div
        style={{
          padding: '1rem 1.5rem',
          borderBottom: '1px solid #dee2e6',
          backgroundColor: 'white',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <h3 style={{ margin: 0, fontSize: '1.1rem' }}>{peerUsername}</h3>
          <div style={{ fontSize: '0.85rem', color: '#6c757d', marginTop: '0.25rem' }}>
            {connected ? '🟢 Connected' : '⚫ Disconnected'}
          </div>
        </div>

        {/* Connection status indicator */}
        {!connected && (
          <div
            style={{
              padding: '0.4rem 0.8rem',
              backgroundColor: '#fff3cd',
              color: '#856404',
              borderRadius: '4px',
              fontSize: '0.85rem',
            }}
          >
            Reconnecting...
          </div>
        )}
      </div>

      {/* Messages */}
      <MessageList
        messages={messages}
        currentUserId={currentUserId}
        peerUserId={peerUserId}
        conversationId={conversationId}
        onLoadMore={handleLoadMore}
        hasMore={hasMore}
      />

      {/* Input */}
      <MessageInput
        currentUserId={currentUserId}
        peerUserId={peerUserId}
        peerUsername={peerUsername}
        socket={socket}
        onMessageSent={handleMessageSent}
      />
    </div>
  );
}
