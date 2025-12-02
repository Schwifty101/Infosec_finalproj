'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { deletePrivateKey } from '@/lib/crypto/keyStorage';

/**
 * Dashboard Page
 * Main authenticated view for logged-in users
 *
 * Features (Phase 1):
 * - Display user info
 * - Logout functionality
 *
 * Future phases will add:
 * - Message list and composition
 * - File sharing
 * - User search
 */
export default function DashboardPage() {
  const router = useRouter();
  const [username, setUsername] = useState<string | null>(null);
  const [userId, setUserId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check authentication on mount
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

  const handleLogout = async () => {
    // Clear session storage
    const currentUserId = sessionStorage.getItem('userId');
    sessionStorage.removeItem('userId');
    sessionStorage.removeItem('username');
    sessionStorage.removeItem('publicKey');

    // Optionally clear private key from IndexedDB (uncomment if desired)
    // if (currentUserId) {
    //   await deletePrivateKey(currentUserId);
    // }

    console.log('✅ Logged out successfully');
    router.push('/login');
  };

  if (loading) {
    return (
      <main style={{ minHeight: '100vh', padding: '2rem' }}>
        <div style={{ textAlign: 'center', marginTop: '2rem' }}>
          <p>Loading...</p>
        </div>
      </main>
    );
  }

  return (
    <main style={{ minHeight: '100vh', padding: '2rem' }}>
      <div style={{ maxWidth: '800px', margin: '0 auto' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <h1>Dashboard</h1>
          <button
            onClick={handleLogout}
            style={{
              padding: '0.5rem 1rem',
              fontSize: '1rem',
              backgroundColor: '#dc3545',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
            }}
          >
            Logout
          </button>
        </div>

        <div style={{ backgroundColor: '#f8f9fa', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem' }}>
          <h2 style={{ marginTop: 0 }}>Welcome, {username}!</h2>
          <p style={{ color: '#666', marginBottom: 0 }}>
            User ID: <code style={{ backgroundColor: '#e9ecef', padding: '0.2rem 0.4rem', borderRadius: '4px' }}>{userId}</code>
          </p>
        </div>

        {/* Messaging Section - Phase 3 */}
        <div style={{ backgroundColor: '#d4edda', border: '1px solid #28a745', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem' }}>
          <h3 style={{ marginTop: 0, color: '#155724' }}>End-to-End Encrypted Messaging</h3>
          <p style={{ color: '#155724', marginBottom: '1rem' }}>
            Send and receive encrypted messages in real-time using WebSocket
          </p>
          <button
            onClick={() => router.push('/messaging')}
            style={{
              padding: '0.75rem 1.5rem',
              fontSize: '1rem',
              backgroundColor: '#28a745',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 'bold',
              marginRight: '0.75rem',
            }}
          >
            Open Messages
          </button>
          <button
            onClick={() => router.push('/key-exchange')}
            style={{
              padding: '0.75rem 1.5rem',
              fontSize: '1rem',
              backgroundColor: '#007bff',
              color: 'white',
              border: 'none',
              borderRadius: '4px',
              cursor: 'pointer',
              fontWeight: 'bold',
            }}
          >
            Manage Key Exchanges
          </button>
        </div>

        {/* System Status */}
        <div style={{ backgroundColor: '#fff', border: '1px solid #dee2e6', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem' }}>
          <h3 style={{ marginTop: 0 }}>System Status</h3>

          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ marginBottom: '0.5rem', color: '#28a745' }}>✅ Phase 1: Authentication & Key Storage</h4>
            <ul style={{ marginLeft: '1.5rem', marginBottom: 0 }}>
              <li>User registration with bcrypt password hashing</li>
              <li>Client-side ECC P-256 identity key generation</li>
              <li>Private key storage in IndexedDB</li>
              <li>Public key storage on server</li>
              <li>User login with key verification</li>
            </ul>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ marginBottom: '0.5rem', color: '#28a745' }}>✅ Phase 2: Secure Key Exchange Protocol</h4>
            <ul style={{ marginLeft: '1.5rem', marginBottom: 0 }}>
              <li>AECDH-ECDSA authenticated key exchange</li>
              <li>Ephemeral ECDH keys for forward secrecy</li>
              <li>ECDSA signatures for MITM protection</li>
              <li>HKDF-SHA256 session key derivation</li>
              <li>Replay protection (nonces + timestamps)</li>
              <li>30-day session key expiration</li>
            </ul>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ marginBottom: '0.5rem', color: '#28a745' }}>✅ Phase 3: End-to-End Encrypted Messaging</h4>
            <ul style={{ marginLeft: '1.5rem', marginBottom: 0 }}>
              <li>AES-256-GCM message encryption with session keys</li>
              <li>Real-time WebSocket messaging (Socket.io)</li>
              <li>Client-side encryption/decryption</li>
              <li>Sequence numbers for replay/reorder protection</li>
              <li>Automatic session key re-exchange on expiration</li>
              <li>WhatsApp-style UI with conversation list</li>
              <li>Cursor-based pagination for message history</li>
            </ul>
          </div>

          <div style={{ marginBottom: '1.5rem' }}>
            <h4 style={{ marginBottom: '0.5rem', color: '#28a745' }}>✅ Phase 4: Encrypted File Sharing</h4>
            <ul style={{ marginLeft: '1.5rem', marginBottom: 0 }}>
              <li>AES-256-GCM file encryption with session keys</li>
              <li>Chunked upload for large files (1MB chunks)</li>
              <li>File metadata encryption (name, size, type)</li>
              <li>Secure file download with decryption</li>
              <li>File attachments in chat messages</li>
            </ul>
          </div>

          <div>
            <h4 style={{ marginBottom: '0.5rem', color: '#28a745' }}>✅ Phase 5: Security Logging & Attack Demos</h4>
            <ul style={{ marginLeft: '1.5rem', marginBottom: 0 }}>
              <li>Comprehensive security event logging</li>
              <li>Admin log viewer with filtering</li>
              <li>Replay attack demonstration & protection</li>
              <li>MITM attack on unsigned DH (vulnerable)</li>
              <li>MITM protection with AECDH-ECDSA (protected)</li>
            </ul>
          </div>
        </div>

        {/* Security Demonstrations */}
        <div style={{ backgroundColor: '#f8d7da', border: '1px solid #dc3545', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem' }}>
          <h3 style={{ marginTop: 0, color: '#721c24' }}>🔐 Security Demonstrations</h3>
          <p style={{ color: '#721c24', marginBottom: '1rem' }}>
            Interactive demonstrations showing attack scenarios and defenses
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
            <button
              onClick={() => router.push('/attack-demos')}
              style={{
                padding: '0.75rem 1.5rem',
                fontSize: '1rem',
                backgroundColor: '#dc3545',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 'bold',
              }}
            >
              🛡️ Attack Demos
            </button>
            <button
              onClick={() => router.push('/logs')}
              style={{
                padding: '0.75rem 1.5rem',
                fontSize: '1rem',
                backgroundColor: '#6c757d',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
                fontWeight: 'bold',
              }}
            >
              📋 Security Logs
            </button>
          </div>
        </div>

        {/* Test Pages */}
        <div style={{ backgroundColor: '#e2e3e5', border: '1px solid #6c757d', padding: '1.5rem', borderRadius: '8px', marginBottom: '2rem' }}>
          <h3 style={{ marginTop: 0, color: '#383d41' }}>🧪 Test & Verification Pages</h3>
          <p style={{ color: '#383d41', marginBottom: '1rem' }}>
            Test pages for verifying cryptographic implementations
          </p>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.75rem' }}>
            <button
              onClick={() => router.push('/test-phase2')}
              style={{
                padding: '0.5rem 1rem',
                fontSize: '0.9rem',
                backgroundColor: '#6c757d',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              Phase 2 Tests
            </button>
            <button
              onClick={() => router.push('/test-phase3')}
              style={{
                padding: '0.5rem 1rem',
                fontSize: '0.9rem',
                backgroundColor: '#6c757d',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              Phase 3 Tests
            </button>
            <button
              onClick={() => router.push('/test-phase4')}
              style={{
                padding: '0.5rem 1rem',
                fontSize: '0.9rem',
                backgroundColor: '#6c757d',
                color: 'white',
                border: 'none',
                borderRadius: '4px',
                cursor: 'pointer',
              }}
            >
              Phase 4 Tests
            </button>
          </div>
        </div>

        {/* Next Steps */}
        <div style={{ backgroundColor: '#d4edda', border: '1px solid #28a745', padding: '1.5rem', borderRadius: '8px' }}>
          <h3 style={{ marginTop: 0, color: '#155724' }}>✅ Project Complete</h3>
          <p style={{ color: '#155724', marginBottom: '0.5rem' }}>
            <strong>All 5 phases implemented:</strong> Authentication, Key Exchange, Messaging, File Sharing, Security Demos
          </p>
          <p style={{ color: '#155724', marginBottom: '0.5rem' }}>
            <strong>Remaining:</strong> STRIDE threat modeling documentation
          </p>
          <p style={{ color: '#155724', marginBottom: 0 }}>
            <strong>Final:</strong> Demo video and project presentation
          </p>
        </div>
      </div>
    </main>
  );
}
