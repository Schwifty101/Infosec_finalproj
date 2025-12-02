/**
 * Messaging Page
 *
 * Main page for end-to-end encrypted messaging
 * WhatsApp-style layout with conversation list and chat window
 */

'use client';

import { Suspense, useEffect, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import ConversationList from '@/app/components/ConversationList';
import ChatWindow from '@/app/components/ChatWindow';
import UserSearch from '@/app/components/UserSearch';
import { getConversationId } from '@/lib/crypto/protocol';

interface SelectedConversation {
  conversationId: string;
  peerUserId: string;
  peerUsername: string;
}

function MessagingContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [userId, setUserId] = useState<string | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedConversation, setSelectedConversation] =
    useState<SelectedConversation | null>(null);
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [refreshConversations, setRefreshConversations] = useState(0);

  useEffect(() => {
    // Check authentication
    const storedUserId = sessionStorage.getItem('userId');
    const storedUsername = sessionStorage.getItem('username');

    if (!storedUserId || !storedUsername) {
      // Not authenticated, redirect to login
      router.push('/login');
      return;
    }

    setUserId(storedUserId);
    setUsername(storedUsername);
    setLoading(false);

    // Check if there's a peer parameter for direct navigation
    const peerParam = searchParams.get('peer');
    if (peerParam && storedUserId) {
      // Fetch peer username and set conversation
      fetchPeerAndSelectConversation(storedUserId, peerParam);
    }
  }, [router, searchParams]);

  // Fetch peer info and select the conversation
  const fetchPeerAndSelectConversation = async (currentUserId: string, peerUserId: string) => {
    try {
      const response = await fetch(`/api/keys/${peerUserId}`);
      const data = await response.json();

      if (data.success && data.username) {
        const conversationId = getConversationId(currentUserId, peerUserId);
        setSelectedConversation({
          conversationId,
          peerUserId,
          peerUsername: data.username,
        });
      }
    } catch (error) {
      console.error('Failed to fetch peer info:', error);
    }
  };

  const handleSelectConversation = (conversation: any) => {
    setSelectedConversation({
      conversationId: conversation.conversationId,
      peerUserId: conversation.peerUserId,
      peerUsername: conversation.peerUsername,
    });
  };

  /**
   * Handle successful key exchange from UserSearch
   * Select the new conversation and close modal
   */
  const handleKeyExchangeComplete = (peerUserId: string, peerUsername: string) => {
    if (!userId) return;

    const conversationId = getConversationId(userId, peerUserId);
    setSelectedConversation({
      conversationId,
      peerUserId,
      peerUsername,
    });
    setShowNewChatModal(false);
    // Trigger conversation list refresh
    setRefreshConversations(prev => prev + 1);
  };

  /**
   * Handle "View Chat" from UserSearch (when session already exists)
   */
  const handleViewChat = (peerUserId: string, peerUsername: string) => {
    if (!userId) return;

    const conversationId = getConversationId(userId, peerUserId);
    setSelectedConversation({
      conversationId,
      peerUserId,
      peerUsername,
    });
    setShowNewChatModal(false);
  };

  const handleBackToDashboard = () => {
    router.push('/dashboard');
  };

  if (loading) {
    return (
      <main
        style={{
          minHeight: '100vh',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#f8f9fa',
        }}
      >
        <div style={{ textAlign: 'center', color: '#6c757d' }}>
          <div
            style={{
              width: '48px',
              height: '48px',
              border: '4px solid #e9ecef',
              borderTop: '4px solid #007bff',
              borderRadius: '50%',
              animation: 'spin 1s linear infinite',
              margin: '0 auto 1rem',
            }}
          />
          Loading...
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
      </main>
    );
  }

  if (!userId || !username) {
    return null; // Will redirect
  }

  return (
    <main
      style={{
        minHeight: '100vh',
        backgroundColor: '#f8f9fa',
        display: 'flex',
        flexDirection: 'column',
      }}
    >
      {/* Top Navigation Bar */}
      <div
        style={{
          backgroundColor: '#007bff',
          color: 'white',
          padding: '1rem 1.5rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <h1 style={{ margin: 0, fontSize: '1.5rem' }}>
            🔐 Secure Messaging
          </h1>
          <div
            style={{
              padding: '0.25rem 0.75rem',
              backgroundColor: 'rgba(255,255,255,0.2)',
              borderRadius: '12px',
              fontSize: '0.85rem',
            }}
          >
            E2E Encrypted
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <button
            onClick={() => setShowNewChatModal(true)}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: '#28a745',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.95rem',
              fontWeight: '500',
            }}
          >
            + New Chat
          </button>
          <button
            onClick={handleBackToDashboard}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: 'rgba(255,255,255,0.2)',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontSize: '0.95rem',
            }}
          >
            ← Dashboard
          </button>
        </div>
      </div>

      {/* Main Content: Conversation List + Chat Window */}
      <div
        style={{
          flex: 1,
          display: 'flex',
          maxHeight: 'calc(100vh - 64px)',
          overflow: 'hidden',
        }}
      >
        {/* Conversation List Sidebar */}
        <ConversationList
          currentUserId={userId}
          currentUsername={username}
          selectedConversationId={selectedConversation?.conversationId || null}
          onSelectConversation={handleSelectConversation}
          refreshKey={refreshConversations}
        />

        {/* Chat Window */}
        {selectedConversation ? (
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <ChatWindow
              currentUserId={userId}
              currentUsername={username}
              peerUserId={selectedConversation.peerUserId}
              peerUsername={selectedConversation.peerUsername}
            />
          </div>
        ) : (
          <div
            style={{
              flex: 1,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              backgroundColor: '#f8f9fa',
            }}
          >
            <div style={{ textAlign: 'center', color: '#6c757d' }}>
              <div style={{ fontSize: '4rem', marginBottom: '1rem' }}>💬</div>
              <div style={{ fontSize: '1.3rem', marginBottom: '0.5rem' }}>
                Select a conversation
              </div>
              <div style={{ fontSize: '0.95rem', opacity: 0.7 }}>
                Choose a conversation from the list to start messaging
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Info Footer */}
      <div
        style={{
          backgroundColor: 'white',
          borderTop: '1px solid #dee2e6',
          padding: '0.75rem 1.5rem',
          textAlign: 'center',
          fontSize: '0.85rem',
          color: '#6c757d',
        }}
      >
        🔒 All messages are end-to-end encrypted with AES-256-GCM • Phase 3
        Complete
      </div>

      {/* New Chat Modal */}
      {showNewChatModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onClick={(e) => {
            // Close modal when clicking backdrop
            if (e.target === e.currentTarget) {
              setShowNewChatModal(false);
            }
          }}
        >
          <div
            style={{
              backgroundColor: 'white',
              borderRadius: '12px',
              padding: '1.5rem',
              width: '90%',
              maxWidth: '500px',
              maxHeight: '80vh',
              overflow: 'auto',
              boxShadow: '0 20px 60px rgba(0, 0, 0, 0.3)',
            }}
          >
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1.5rem',
              }}
            >
              <h2 style={{ margin: 0, fontSize: '1.3rem' }}>
                🆕 Start New Conversation
              </h2>
              <button
                onClick={() => setShowNewChatModal(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  fontSize: '1.5rem',
                  cursor: 'pointer',
                  color: '#6c757d',
                  padding: '0.25rem',
                  lineHeight: 1,
                }}
              >
                ✕
              </button>
            </div>

            <p
              style={{
                color: '#6c757d',
                marginBottom: '1rem',
                fontSize: '0.95rem',
              }}
            >
              Search for a user to start a secure, encrypted conversation.
              You&apos;ll need to complete a key exchange before messaging.
            </p>

            <UserSearch
              currentUserId={userId}
              currentUsername={username}
              onKeyExchangeInitiated={handleKeyExchangeComplete}
              onViewChat={handleViewChat}
            />
          </div>
        </div>
      )}
    </main>
  );
}

export default function MessagingPage() {
  return (
    <Suspense fallback={
      <main style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', backgroundColor: '#f8f9fa' }}>
        <div style={{ textAlign: 'center', color: '#6c757d' }}>Loading...</div>
      </main>
    }>
      <MessagingContent />
    </Suspense>
  );
}
