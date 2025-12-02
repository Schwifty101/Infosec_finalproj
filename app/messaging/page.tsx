/**
 * Messaging Page
 *
 * Main page for end-to-end encrypted messaging
 * WhatsApp-style layout with conversation list and chat window
 */

'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import ConversationList from '@/app/components/ConversationList';
import ChatWindow from '@/app/components/ChatWindow';

interface SelectedConversation {
  conversationId: string;
  peerUserId: string;
  peerUsername: string;
}

export default function MessagingPage() {
  const router = useRouter();
  const [userId, setUserId] = useState<string | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedConversation, setSelectedConversation] =
    useState<SelectedConversation | null>(null);

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
  }, [router]);

  const handleSelectConversation = (conversation: any) => {
    setSelectedConversation({
      conversationId: conversation.conversationId,
      peerUserId: conversation.peerUserId,
      peerUsername: conversation.peerUsername,
    });
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
    </main>
  );
}
