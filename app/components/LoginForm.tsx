'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { getPrivateKey } from '@/lib/crypto/keyStorage';
import type { ILoginResponse } from '@/types';

/**
 * Login Form Component
 * Handles user authentication and private key verification
 *
 * Flow:
 * 1. User submits username/password
 * 2. Call API to authenticate
 * 3. Verify private key exists in IndexedDB
 * 4. Store session info in sessionStorage
 * 5. Redirect to dashboard
 */
export default function LoginForm() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Step 1: Authenticate user
      setStep('Authenticating...');
      const loginRes = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const loginData: ILoginResponse = await loginRes.json();

      if (!loginData.success) {
        setError(loginData.message);
        setLoading(false);
        return;
      }

      const userId = loginData.userId!;
      const loggedInUsername = loginData.username!;
      const publicKey = loginData.publicKey;

      // Step 2: Verify private key exists in IndexedDB
      setStep('Verifying encryption keys...');
      console.log('🔐 Checking for private key in IndexedDB...');
      const privateKeyJwk = await getPrivateKey(userId);

      if (!privateKeyJwk) {
        setError(
          'Private key not found. Your encryption keys may have been lost. Please register a new account.'
        );
        setLoading(false);
        return;
      }

      console.log('✅ Private key found in IndexedDB');

      // Step 3: Store session info in sessionStorage
      setStep('Loading dashboard...');
      console.log('💾 Storing session info...');
      sessionStorage.setItem('userId', userId);
      sessionStorage.setItem('username', loggedInUsername);
      if (publicKey) {
        sessionStorage.setItem('publicKey', publicKey);
      }

      console.log('✅ Login successful!');

      // Step 4: Redirect to dashboard
      setStep('Login complete!');
      setTimeout(() => {
        router.push('/dashboard');
      }, 500);

    } catch (err: any) {
      console.error('❌ Login error:', err);
      setError(err.message || 'Login failed. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto', padding: '2rem' }}>
      <h2>Login</h2>
      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        <div>
          <label htmlFor="username" style={{ display: 'block', marginBottom: '0.5rem' }}>
            Username
          </label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.5rem',
              fontSize: '1rem',
              border: '1px solid #ccc',
              borderRadius: '4px',
            }}
          />
        </div>

        <div>
          <label htmlFor="password" style={{ display: 'block', marginBottom: '0.5rem' }}>
            Password
          </label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.5rem',
              fontSize: '1rem',
              border: '1px solid #ccc',
              borderRadius: '4px',
            }}
          />
        </div>

        {error && (
          <div style={{ color: 'red', padding: '0.5rem', backgroundColor: '#fee', borderRadius: '4px' }}>
            {error}
          </div>
        )}

        {step && !error && (
          <div style={{ color: 'blue', padding: '0.5rem', backgroundColor: '#eef', borderRadius: '4px' }}>
            {step}
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          style={{
            padding: '0.75rem',
            fontSize: '1rem',
            backgroundColor: loading ? '#ccc' : '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: loading ? 'not-allowed' : 'pointer',
          }}
        >
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>

      <p style={{ marginTop: '1rem', textAlign: 'center' }}>
        Don&apos;t have an account?{' '}
        <a href="/register" style={{ color: '#007bff', textDecoration: 'none' }}>
          Register here
        </a>
      </p>
    </div>
  );
}
