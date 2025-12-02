'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import {
  initiateKeyExchange,
  handleKeyExchangeInit,
  handleKeyExchangeResponse,
  handleKeyExchangeConfirm,
} from '@/lib/crypto/protocol';
import type {
  KeyExchangeInitMessage,
  PendingKeyExchangesResponse,
  InitiateKeyExchangeRequest,
  RespondKeyExchangeRequest,
  ConfirmKeyExchangeRequest,
} from '@/types';
import { KEY_EXCHANGE_CONFIG } from '@/types/keyExchange';
import UserSearch from './UserSearch';

interface Props {
  currentUserId: string;
  currentUsername: string;
}

/**
 * Key Exchange Manager Component
 *
 * Handles:
 * - Listing available users for key exchange
 * - Displaying pending incoming requests
 * - Initiating key exchange
 * - Responding to key exchange requests
 * - Polling for pending requests
 */
export default function KeyExchangeManager({ currentUserId, currentUsername }: Props) {
  const router = useRouter();
  const [pendingRequests, setPendingRequests] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [processingSessionId, setProcessingSessionId] = useState<string | null>(null);

  /**
   * Handle successful key exchange initiation
   * Auto-redirect to messaging page
   */
  const handleKeyExchangeComplete = (peerUserId: string, peerUsername: string) => {
    setSuccessMessage(`🔒 Secure session established with ${peerUsername}! Redirecting to messaging...`);
    setTimeout(() => {
      router.push(`/messaging?peer=${peerUserId}`);
    }, 1500);
  };

  // Fetch pending key exchange requests
  const fetchPendingRequests = async () => {
    try {
      const response = await fetch(`/api/key-exchange/pending/${currentUserId}`);
      const data: PendingKeyExchangesResponse = await response.json();

      if (data.success) {
        setPendingRequests(data.exchanges);
        console.log(`📥 Found ${data.exchanges.length} pending key exchange requests`);
      }
    } catch (err) {
      console.error('Failed to fetch pending requests:', err);
    }
  };

  // Poll for pending requests every 10 seconds
  useEffect(() => {
    fetchPendingRequests();

    const interval = setInterval(() => {
      fetchPendingRequests();
    }, KEY_EXCHANGE_CONFIG.POLL_INTERVAL_MS);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUserId]);

  // Accept a pending key exchange request
  const handleAcceptRequest = async (request: any) => {
    setLoading(true);
    setError('');
    setSuccessMessage('');
    setProcessingSessionId(request.sessionId);

    try {
      console.log('🔐 Accepting key exchange from', request.fromUsername);

      // Step 1: Fetch initiator's public key from server
      const keyResponse = await fetch(`/api/keys/${request.fromUserId}`);
      const keyData = await keyResponse.json();

      if (!keyData.success || !keyData.publicKey) {
        throw new Error('Failed to retrieve initiator public key');
      }

      // TOFU: Validate public key
      const { validatePublicKey, storeKeyFingerprint, formatFingerprint } =
        await import('@/lib/crypto/keyValidation');

      const validation = await validatePublicKey(request.fromUserId, keyData.publicKey);

      if (!validation.valid) {
        // Key changed - potential MITM!
        const confirmChange = confirm(
          `⚠️ WARNING: ${request.fromUsername}'s public key has changed!\n\n` +
          `${validation.reason}\n\n` +
          `New Fingerprint: ${formatFingerprint(validation.fingerprint)}\n\n` +
          `This could indicate a Man-in-the-Middle attack. Only proceed if you've ` +
          `verified this change with ${request.fromUsername} through a secure channel ` +
          `(phone call, in person, etc.).\n\n` +
          `Do you want to proceed anyway?`
        );

        if (!confirmChange) {
          throw new Error('Key exchange rejected due to public key change');
        }

        // User accepted - update fingerprint
        await storeKeyFingerprint(request.fromUserId, keyData.publicKey, validation.fingerprint);
      }

      if (validation.isFirstSeen) {
        console.log('First exchange with user - storing fingerprint:',
          formatFingerprint(validation.fingerprint));
        await storeKeyFingerprint(request.fromUserId, keyData.publicKey, validation.fingerprint);
      }

      // Step 2: Handle init message and generate response (client-side)
      const responseMessage = await handleKeyExchangeInit(
        request.initMessage,
        currentUserId,
        keyData.publicKey
      );

      // Step 3: Send response message to server
      const response = await fetch('/api/key-exchange/respond', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: responseMessage,
        } as RespondKeyExchangeRequest),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message);
      }

      console.log('✅ Key exchange response sent, waiting for confirmation...');

      // Poll for confirmation
      const sessionId = request.sessionId;
      const pollInterval = 2000; // 2 seconds
      const maxAttempts = 150; // 5 minutes
      let attempts = 0;

      const pollForConfirmation = async (): Promise<boolean> => {
        while (attempts < maxAttempts) {
          attempts++;

          try {
            const statusResponse = await fetch(`/api/key-exchange/status/${sessionId}`);
            if (!statusResponse.ok) {
              await new Promise(resolve => setTimeout(resolve, pollInterval));
              continue;
            }

            const statusData = await statusResponse.json();

            if (statusData.status === 'confirmed' && statusData.confirmMessage) {
              console.log('📥 Received confirmation, verifying HMAC...');

              // Verify confirmation tag
              const confirmValid = await handleKeyExchangeConfirm(
                statusData.confirmMessage,
                currentUserId
              );

              if (!confirmValid) {
                throw new Error('Confirmation tag verification failed - possible MITM!');
              }

              console.log('✅ Confirmation verified! Session key confirmed identical.');
              return true;
            }

            if (statusData.status === 'failed' || statusData.status === 'rejected') {
              throw new Error('Key exchange rejected or failed');
            }

            await new Promise(resolve => setTimeout(resolve, pollInterval));
          } catch (pollError) {
            console.error('Polling error:', pollError);
            await new Promise(resolve => setTimeout(resolve, pollInterval));
          }
        }

        return false;
      };

      const confirmed = await pollForConfirmation();

      if (!confirmed) {
        throw new Error('Confirmation timeout - initiator did not complete within 5 minutes');
      }

      // Success - redirect to messaging
      setSuccessMessage(`🔒 Secure session established with ${request.fromUsername}!`);
      setPendingRequests(prev => prev.filter(r => r.sessionId !== request.sessionId));

      setTimeout(() => {
        router.push(`/messaging?peer=${request.fromUserId}`);
      }, 1500);
    } catch (err: any) {
      console.error('❌ Failed to accept key exchange:', err);
      setError(err.message || 'Failed to accept key exchange request');
    } finally {
      setLoading(false);
      setProcessingSessionId(null);
    }
  };

  // Reject a pending key exchange request
  const handleRejectRequest = async (sessionId: string) => {
    setPendingRequests((prev) => prev.filter((r) => r.sessionId !== sessionId));
    console.log('❌ Key exchange request rejected');
  };

  return (
    <div style={{ maxWidth: '800px', margin: '0 auto' }}>
      <h2>Key Exchange Manager</h2>

      {/* Status Messages */}
      {error && (
        <div
          style={{
            padding: '1rem',
            marginBottom: '1rem',
            backgroundColor: '#fee',
            color: 'red',
            borderRadius: '4px',
          }}
        >
          {error}
        </div>
      )}

      {successMessage && (
        <div
          style={{
            padding: '1rem',
            marginBottom: '1rem',
            backgroundColor: '#efe',
            color: 'green',
            borderRadius: '4px',
          }}
        >
          {successMessage}
        </div>
      )}

      {/* User Search Section */}
      <div style={{ marginBottom: '2rem' }}>
        <h3>🔍 Find Users to Chat With</h3>
        <p style={{ color: '#666', marginBottom: '1rem' }}>
          Search for users by username to start a secure conversation
        </p>
        <UserSearch
          currentUserId={currentUserId}
          currentUsername={currentUsername}
          onKeyExchangeInitiated={handleKeyExchangeComplete}
        />
      </div>

      {/* Pending Requests Section */}
      <div style={{ marginBottom: '2rem' }}>
        <h3>
          Pending Requests
          {pendingRequests.length > 0 && (
            <span
              style={{
                marginLeft: '0.5rem',
                padding: '0.25rem 0.5rem',
                backgroundColor: '#007bff',
                color: 'white',
                borderRadius: '12px',
                fontSize: '0.9rem',
              }}
            >
              {pendingRequests.length}
            </span>
          )}
        </h3>

        {pendingRequests.length === 0 ? (
          <p style={{ color: '#666' }}>No pending key exchange requests</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {pendingRequests.map((request) => (
              <div
                key={request.sessionId}
                style={{
                  padding: '1rem',
                  border: '1px solid #ddd',
                  borderRadius: '8px',
                  backgroundColor: '#f8f9fa',
                }}
              >
                <div style={{ marginBottom: '0.5rem' }}>
                  <strong>{request.fromUsername}</strong> wants to start a secure conversation
                </div>
                <div style={{ fontSize: '0.9rem', color: '#666', marginBottom: '1rem' }}>
                  Received: {new Date(request.createdAt).toLocaleString()}
                </div>
                <div style={{ display: 'flex', gap: '0.5rem' }}>
                  <button
                    onClick={() => handleAcceptRequest(request)}
                    disabled={loading && processingSessionId === request.sessionId}
                    style={{
                      padding: '0.5rem 1rem',
                      backgroundColor: loading && processingSessionId === request.sessionId ? '#ccc' : '#28a745',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: loading && processingSessionId === request.sessionId ? 'not-allowed' : 'pointer',
                    }}
                  >
                    {loading && processingSessionId === request.sessionId ? 'Accepting...' : 'Accept'}
                  </button>
                  <button
                    onClick={() => handleRejectRequest(request.sessionId)}
                    disabled={loading}
                    style={{
                      padding: '0.5rem 1rem',
                      backgroundColor: '#dc3545',
                      color: 'white',
                      border: 'none',
                      borderRadius: '4px',
                      cursor: loading ? 'not-allowed' : 'pointer',
                    }}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Instructions */}
      <div
        style={{
          padding: '1rem',
          backgroundColor: '#e7f3ff',
          borderRadius: '8px',
          marginTop: '2rem',
        }}
      >
        <h4 style={{ marginTop: 0 }}>How Key Exchange Works:</h4>
        <ol style={{ marginBottom: 0, lineHeight: '1.8' }}>
          <li>Alice initiates a key exchange request with Bob</li>
          <li>Bob receives the request and can accept or reject it</li>
          <li>If accepted, both parties derive the same session key</li>
          <li>The session key is used for end-to-end encrypted messaging</li>
          <li>Session keys expire after 30 days for security</li>
        </ol>
      </div>

      {/* Debug Info */}
      <div style={{ marginTop: '2rem', fontSize: '0.9rem', color: '#666' }}>
        <p>Current User: {currentUsername} (ID: {currentUserId})</p>
        <p>Polling for requests every {KEY_EXCHANGE_CONFIG.POLL_INTERVAL_MS / 1000} seconds</p>
      </div>
    </div>
  );
}
