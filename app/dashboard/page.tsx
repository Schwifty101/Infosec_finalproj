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

        <div style={{ backgroundColor: '#fff', border: '1px solid #dee2e6', padding: '1.5rem', borderRadius: '8px' }}>
          <h3 style={{ marginTop: 0 }}>Phase 1 Complete</h3>
          <p>Authentication system is now operational with:</p>
          <ul>
            <li>User registration with secure password hashing</li>
            <li>Client-side ECC P-256 key generation</li>
            <li>Private key storage in IndexedDB</li>
            <li>Public key storage on server</li>
            <li>User login with key verification</li>
          </ul>
          <p style={{ color: '#666', fontSize: '0.9rem', marginBottom: 0 }}>
            Future phases will add messaging, file sharing, and security features.
          </p>
        </div>
      </div>
    </main>
  );
}
