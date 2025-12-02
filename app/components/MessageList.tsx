/**
 * Message List Component
 *
 * Scrollable list of messages with cursor-based pagination
 * Automatically scrolls to bottom on new messages
 * Loads older messages when scrolling to top
 */

'use client';

import { useRef, useEffect, useState } from 'react';
import MessageBubble from './MessageBubble';

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
  messages: Message[];
  currentUserId: string;
  peerUserId: string;
  conversationId: string;
  onLoadMore: (cursor: string) => Promise<void>;
  hasMore: boolean;
}

export default function MessageList({
  messages,
  currentUserId,
  peerUserId,
  conversationId,
  onLoadMore,
  hasMore,
}: Props) {
  const scrollContainerRef = useRef<HTMLDivElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [isAtBottom, setIsAtBottom] = useState(true);
  const previousScrollHeight = useRef(0);

  // Scroll to bottom on initial load or new messages (when already at bottom)
  useEffect(() => {
    if (isAtBottom && bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isAtBottom]);

  // Handle scroll events for pagination
  const handleScroll = async (e: React.UIEvent<HTMLDivElement>) => {
    const container = e.currentTarget;
    const { scrollTop, scrollHeight, clientHeight } = container;

    // Check if at bottom
    const atBottom = scrollHeight - scrollTop - clientHeight < 50;
    setIsAtBottom(atBottom);

    // Check if scrolled to top (load more)
    if (scrollTop < 100 && !loadingMore && hasMore) {
      setLoadingMore(true);

      // Store current scroll position
      previousScrollHeight.current = scrollHeight;

      // Get oldest message ID as cursor
      if (messages.length > 0) {
        const oldestMessage = messages[0];
        await onLoadMore(oldestMessage._id);

        // Restore scroll position after loading
        setTimeout(() => {
          if (scrollContainerRef.current) {
            const newScrollHeight = scrollContainerRef.current.scrollHeight;
            const heightDiff = newScrollHeight - previousScrollHeight.current;
            scrollContainerRef.current.scrollTop = heightDiff;
          }
        }, 100);
      }

      setLoadingMore(false);
    }
  };

  // Scroll to bottom on mount
  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView();
    }
  }, [conversationId]); // Reset when conversation changes

  return (
    <div
      ref={scrollContainerRef}
      onScroll={handleScroll}
      style={{
        flex: 1,
        overflowY: 'auto',
        padding: '1rem 0',
        backgroundColor: '#f8f9fa',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Loading indicator for pagination */}
      {loadingMore && (
        <div
          style={{
            textAlign: 'center',
            padding: '1rem',
            color: '#6c757d',
            fontSize: '0.9rem',
          }}
        >
          <div
            style={{
              display: 'inline-block',
              width: '20px',
              height: '20px',
              border: '3px solid #e9ecef',
              borderTop: '3px solid #007bff',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
            }}
          />
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

      {/* "No more messages" indicator */}
      {!hasMore && messages.length > 0 && (
        <div
          style={{
            textAlign: 'center',
            padding: '1rem',
            color: '#6c757d',
            fontSize: '0.85rem',
          }}
        >
          Beginning of conversation
        </div>
      )}

      {/* Empty state */}
      {messages.length === 0 && (
        <div
          style={{
            flex: 1,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#6c757d',
            textAlign: 'center',
            padding: '2rem',
          }}
        >
          <div>
            <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>💬</div>
            <div style={{ fontSize: '1.1rem', marginBottom: '0.5rem' }}>
              No messages yet
            </div>
            <div style={{ fontSize: '0.9rem', opacity: 0.7 }}>
              Start a secure conversation!
            </div>
          </div>
        </div>
      )}

      {/* Messages */}
      {messages.map((message) => (
        <MessageBubble
          key={message._id}
          message={message}
          currentUserId={currentUserId}
          peerUserId={peerUserId}
        />
      ))}

      {/* Scroll anchor */}
      <div ref={bottomRef} />
    </div>
  );
}
