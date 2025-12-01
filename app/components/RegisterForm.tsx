'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { generateKeyPair, exportPublicKey, exportPrivateKey } from '@/lib/crypto/keyGeneration';
import { storePrivateKey } from '@/lib/crypto/keyStorage';
import type { IRegisterResponse, IKeyStoreResponse } from '@/types';

/**
 * Registration Form Component
 * Handles user registration with client-side key generation
 *
 * Flow:
 * 1. User submits username/password
 * 2. Call API to create account
 * 3. Generate ECC P-256 key pair (client-side)
 * 4. Store private key in IndexedDB
 * 5. Send public key to server
 * 6. Redirect to login or dashboard
 */
export default function RegisterForm() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      // Validate passwords match
      if (password !== confirmPassword) {
        setError('Passwords do not match');
        setLoading(false);
        return;
      }

      // Validate password strength
      if (password.length < 8) {
        setError('Password must be at least 8 characters');
        setLoading(false);
        return;
      }

      // Step 1: Register user account
      setStep('Creating account...');
      const registerRes = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });

      const registerData: IRegisterResponse = await registerRes.json();

      if (!registerData.success) {
        setError(registerData.message);
        setLoading(false);
        return;
      }

      const userId = registerData.userId!;

      // Step 2: Generate cryptographic key pair (CLIENT-SIDE ONLY)
      setStep('Generating encryption keys...');
      console.log('🔐 Generating ECC P-256 key pair...');
      const keyPair = await generateKeyPair();

      // Step 3: Export keys
      const publicKeyJwk = await exportPublicKey(keyPair.publicKey);
      const privateKeyJwk = await exportPrivateKey(keyPair.privateKey);

      // Step 4: Store private key in IndexedDB (CLIENT-SIDE ONLY)
      setStep('Securing private key...');
      console.log('💾 Storing private key in IndexedDB...');
      await storePrivateKey(userId, privateKeyJwk);
      console.log('✅ Private key stored securely');

      // Step 5: Send public key to server
      setStep('Uploading public key...');
      console.log('📤 Sending public key to server...');
      const keyStoreRes = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ userId, publicKey: publicKeyJwk }),
      });

      const keyStoreData: IKeyStoreResponse = await keyStoreRes.json();

      if (!keyStoreData.success) {
        setError('Failed to store public key: ' + keyStoreData.message);
        setLoading(false);
        return;
      }

      console.log('✅ Public key stored on server');
      console.log('✅ Registration complete!');

      // Step 6: Redirect to login
      setStep('Registration complete!');
      setTimeout(() => {
        router.push('/login');
      }, 1000);

    } catch (err: any) {
      console.error('❌ Registration error:', err);
      setError(err.message || 'Registration failed. Please try again.');
      setLoading(false);
    }
  };

  return (
    <div style={{ maxWidth: '400px', margin: '0 auto', padding: '2rem' }}>
      <h2>Register</h2>
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
            minLength={3}
            maxLength={20}
            pattern="[a-zA-Z0-9_]+"
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.5rem',
              fontSize: '1rem',
              border: '1px solid #ccc',
              borderRadius: '4px',
            }}
          />
          <small style={{ color: '#666' }}>3-20 alphanumeric characters</small>
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
            minLength={8}
            disabled={loading}
            style={{
              width: '100%',
              padding: '0.5rem',
              fontSize: '1rem',
              border: '1px solid #ccc',
              borderRadius: '4px',
            }}
          />
          <small style={{ color: '#666' }}>Minimum 8 characters</small>
        </div>

        <div>
          <label htmlFor="confirmPassword" style={{ display: 'block', marginBottom: '0.5rem' }}>
            Confirm Password
          </label>
          <input
            type="password"
            id="confirmPassword"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            minLength={8}
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
          {loading ? 'Registering...' : 'Register'}
        </button>
      </form>

      <p style={{ marginTop: '1rem', textAlign: 'center' }}>
        Already have an account?{' '}
        <a href="/login" style={{ color: '#007bff', textDecoration: 'none' }}>
          Login here
        </a>
      </p>
    </div>
  );
}
