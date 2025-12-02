/**
 * Message Input Component
 *
 * Critical component that handles:
 * - Message composition
 * - Session key validation and expiration checking
 * - Automatic key re-exchange on expiration
 * - Message encryption
 * - Sending via WebSocket and API
 */

'use client';

import { useState, useRef, KeyboardEvent } from 'react';
import { Socket } from 'socket.io-client';
import { encryptMessage, getNextSequenceNumber } from '@/lib/crypto/messaging-client';
import { getSessionKey, getSessionMetadata } from '@/lib/crypto/sessionKeys';
import { getConversationId } from '@/lib/crypto/keyExchange';
import { initiateKeyExchange } from '@/lib/crypto/protocol';

interface Props {
  currentUserId: string;
  peerUserId: string;
  peerUsername: string;
  socket: Socket | null;
  onMessageSent: (message: any) => void;
}

export default function MessageInput({
  currentUserId,
  peerUserId,
  peerUsername,
  socket,
  onMessageSent,
}: Props) {
  const [text, setText] = useState('');
  const [sending, setSending] = useState(false);
  const [keyExchangeStatus, setKeyExchangeStatus] = useState('');
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const conversationId = getConversationId(currentUserId, peerUserId);

  const handleSend = async () => {
    const trimmedText = text.trim();
    if (!trimmedText) return;

    setSending(true);
    setKeyExchangeStatus('');

    try {
      // 1. Get session key
      let sessionKey = await getSessionKey(conversationId);

      if (!sessionKey) {
        // No session key - prompt user to initiate key exchange
        const shouldExchange = confirm(
          `No secure session established with ${peerUsername}.\n\nWould you like to initiate a secure key exchange?`
        );

        if (!shouldExchange) {
          setSending(false);
          return;
        }

        // Initiate key exchange
        setKeyExchangeStatus('Establishing secure connection...');
        await handleKeyExchange();
        setSending(false);
        return;
      }

      // 2. Check session key expiration (AUTOMATIC RE-EXCHANGE)
      const metadata = await getSessionMetadata(conversationId);
      if (metadata && metadata.expiresAt) {
        const now = new Date();
        const expiresAt = new Date(metadata.expiresAt);

        if (now > expiresAt) {
          console.warn('Session key expired, triggering automatic re-exchange');
          setKeyExchangeStatus('Refreshing secure connection...');

          try {
            await autoReExchange();
            setKeyExchangeStatus('Secure connection refreshed!');

            // Get new session key
            sessionKey = await getSessionKey(conversationId);

            if (!sessionKey) {
              throw new Error('Failed to retrieve new session key');
            }
          } catch (error) {
            console.error('Auto re-exchange failed:', error);
            setKeyExchangeStatus('Failed to refresh connection. Please try again.');
            setSending(false);
            return;
          }
        }
      }

      // 3. Get sequence number
      const sequenceNumber = await getNextSequenceNumber(conversationId);

      // 4. Encrypt message
      const encrypted = await encryptMessage(trimmedText, sessionKey, sequenceNumber);

      // 5. Store in database via API
      const response = await fetch('/api/messages/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          senderId: currentUserId,
          receiverId: peerUserId,
          ...encrypted,
        }),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Failed to send message');
      }

      // 6. Send via WebSocket for real-time delivery
      if (socket && socket.connected) {
        socket.emit('message:send', {
          receiverId: peerUserId,
          message: {
            _id: data.messageId,
            senderId: currentUserId,
            receiverId: peerUserId,
            ...encrypted,
            timestamp: new Date(data.timestamp),
          },
        });
      }

      // 7. Notify parent component
      onMessageSent({
        _id: data.messageId,
        senderId: currentUserId,
        receiverId: peerUserId,
        ...encrypted,
        timestamp: new Date(data.timestamp),
        delivered: false,
        read: false,
      });

      // Clear input
      setText('');
      setKeyExchangeStatus('');
    } catch (error: any) {
      console.error('Failed to send message:', error);
      alert(`Failed to send message: ${error.message}`);
    } finally {
      setSending(false);
    }
  };

  const handleKeyExchange = async () => {
    try {
      // Use Phase 2 protocol
      const initMessage = await initiateKeyExchange(currentUserId, peerUserId);

      await fetch('/api/key-exchange/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: initMessage }),
      });

      alert(
        `Key exchange request sent to ${peerUsername}.\n\nPlease wait for them to accept the request before sending messages.`
      );
    } catch (error: any) {
      console.error('Key exchange failed:', error);
      alert(`Failed to initiate key exchange: ${error.message}`);
    }
  };

  const autoReExchange = async (): Promise<void> => {
    try {
      // Use existing Phase 2 protocol
      const initMessage = await initiateKeyExchange(currentUserId, peerUserId);

      await fetch('/api/key-exchange/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: initMessage }),
      });

      // Wait for key exchange completion (polling)
      const maxAttempts = 30; // 30 seconds
      for (let i = 0; i < maxAttempts; i++) {
        await new Promise((resolve) => setTimeout(resolve, 1000));

        const sessionKey = await getSessionKey(conversationId);
        if (sessionKey) {
          console.log('✅ Automatic key re-exchange successful');
          return;
        }
      }

      throw new Error('Key exchange timeout');
    } catch (error) {
      console.error('Automatic re-exchange failed:', error);
      throw new Error('Failed to refresh secure connection');
    }
  };

  const handleKeyPress = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleTyping = () => {
    // TODO: Implement typing indicators (Phase 3.8)
    if (socket && socket.connected) {
      socket.emit('typing:start', { receiverId: peerUserId });
    }
  };

  return (
    <div
      style={{
        borderTop: '1px solid #dee2e6',
        padding: '1rem',
        backgroundColor: 'white',
      }}
    >
      {/* Key exchange status */}
      {keyExchangeStatus && (
        <div
          style={{
            marginBottom: '0.75rem',
            padding: '0.5rem 0.75rem',
            backgroundColor: '#fff3cd',
            color: '#856404',
            borderRadius: '4px',
            fontSize: '0.9rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <div
            style={{
              width: '16px',
              height: '16px',
              border: '2px solid #856404',
              borderTop: '2px solid transparent',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
            }}
          />
          {keyExchangeStatus}
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
      )}

      {/* Input area */}
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'flex-end' }}>
        <textarea
          ref={textareaRef}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            handleTyping();
          }}
          onKeyPress={handleKeyPress}
          placeholder={`Message ${peerUsername}...`}
          disabled={sending}
          rows={1}
          style={{
            flex: 1,
            padding: '0.75rem',
            border: '1px solid #ced4da',
            borderRadius: '20px',
            fontSize: '0.95rem',
            resize: 'none',
            maxHeight: '120px',
            fontFamily: 'inherit',
            outline: 'none',
            backgroundColor: sending ? '#f8f9fa' : 'white',
          }}
          onInput={(e: any) => {
            // Auto-resize textarea
            e.target.style.height = 'auto';
            e.target.style.height = e.target.scrollHeight + 'px';
          }}
        />

        <button
          onClick={handleSend}
          disabled={sending || !text.trim()}
          style={{
            padding: '0.75rem 1.5rem',
            backgroundColor:
              sending || !text.trim() ? '#6c757d' : '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '20px',
            fontSize: '0.95rem',
            fontWeight: 'bold',
            cursor: sending || !text.trim() ? 'not-allowed' : 'pointer',
            transition: 'background-color 0.2s',
            whiteSpace: 'nowrap',
          }}
        >
          {sending ? 'Sending...' : 'Send'}
        </button>
      </div>

      {/* Hint */}
      <div
        style={{
          marginTop: '0.5rem',
          fontSize: '0.75rem',
          color: '#6c757d',
          textAlign: 'center',
        }}
      >
        Press Enter to send, Shift+Enter for new line
      </div>
    </div>
  );
}
