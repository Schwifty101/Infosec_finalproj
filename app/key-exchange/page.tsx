'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import KeyExchangeManager from '@/app/components/KeyExchangeManager';

/**
 * Key Exchange Page
 *
 * Dedicated page for managing key exchange operations
 * Requires user to be logged in
 */
export default function KeyExchangePage() {
  const router = useRouter();
  const [userId, setUserId] = useState<string | null>(null);
  const [username, setUsername] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

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

  if (loading) {
    return (
      <main style={{ minHeight: '100vh', padding: '2rem' }}>
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <p>Loading...</p>
        </div>
      </main>
    );
  }

  if (!userId || !username) {
    return null; // Will redirect
  }

  return (
    <main style={{ minHeight: '100vh', padding: '2rem' }}>
      <div style={{ maxWidth: '1200px', margin: '0 auto' }}>
        {/* Header */}
        <div style={{ marginBottom: '2rem', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1 style={{ marginBottom: '0.5rem' }}>Key Exchange</h1>
            <p style={{ color: '#666', margin: 0 }}>
              Establish secure session keys with other users for end-to-end encrypted messaging
            </p>
          </div>
          <button
            onClick={() => router.push('/dashboard')}
            style={{
              padding: '0.5rem 1rem',
              backgroundColor: '#6c757d',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            Back to Dashboard
          </button>
        </div>

        {/* Key Exchange Manager */}
        <KeyExchangeManager currentUserId={userId} currentUsername={username} />

        {/* Info Section */}
        <div
          style={{
            marginTop: '3rem',
            padding: '1.5rem',
            backgroundColor: '#fff3cd',
            border: '1px solid #ffc107',
            borderRadius: '8px',
          }}
        >
          <h3 style={{ marginTop: 0, color: '#856404' }}>Security Information</h3>
          <ul style={{ marginBottom: 0, lineHeight: '1.8', color: '#856404' }}>
            <li>
              <strong>Ephemeral Keys:</strong> Each key exchange uses fresh ephemeral ECDH keys for forward
              secrecy
            </li>
            <li>
              <strong>Authentication:</strong> All messages are signed with your ECDSA identity key to prevent
              man-in-the-middle attacks
            </li>
            <li>
              <strong>Session Keys:</strong> Derived session keys are stored locally in IndexedDB and never
              sent to the server
            </li>
            <li>
              <strong>Expiration:</strong> Session keys expire after 30 days and must be re-exchanged
            </li>
            <li>
              <strong>Replay Protection:</strong> Nonces and timestamps prevent replay attacks
            </li>
          </ul>
        </div>
      </div>
    </main>
  );
}
