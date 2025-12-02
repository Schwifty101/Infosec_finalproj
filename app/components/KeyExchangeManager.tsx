'use client';

import { useState, useEffect } from 'react';
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

interface User {
  _id: string;
  username: string;
}

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
  const [users, setUsers] = useState<User[]>([]);
  const [pendingRequests, setPendingRequests] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [processingSessionId, setProcessingSessionId] = useState<string | null>(null);

  // Fetch all users
  const fetchUsers = async () => {
    try {
      // In a real app, you'd have an API endpoint to list users
      // For now, we'll just show a placeholder
      setUsers([]);
    } catch (err) {
      console.error('Failed to fetch users:', err);
    }
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
    fetchUsers();
    fetchPendingRequests();

    const interval = setInterval(() => {
      fetchPendingRequests();
    }, KEY_EXCHANGE_CONFIG.POLL_INTERVAL_MS);

    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentUserId]);

  // Initiate key exchange with a user
  const handleInitiateKeyExchange = async (peerUserId: string, peerUsername: string) => {
    setLoading(true);
    setError('');
    setSuccessMessage('');

    try {
      console.log('🔐 Initiating key exchange with', peerUsername);

      // Step 1: Generate init message (client-side)
      const initMessage = await initiateKeyExchange(currentUserId, peerUserId);

      // Step 2: Send init message to server
      const response = await fetch('/api/key-exchange/initiate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: initMessage,
        } as InitiateKeyExchangeRequest),
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message);
      }

      setSuccessMessage(`Key exchange initiated with ${peerUsername}. Waiting for response...`);
      console.log('✅ Key exchange initiated successfully');

      // Poll for response (in a real app, you'd use WebSocket or polling)
      setTimeout(() => {
        setSuccessMessage('');
      }, 5000);
    } catch (err: any) {
      console.error('❌ Key exchange initiation failed:', err);
      setError(err.message || 'Failed to initiate key exchange');
    } finally {
      setLoading(false);
    }
  };

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

      setSuccessMessage(`Key exchange accepted with ${request.fromUsername}. Waiting for confirmation...`);
      console.log('✅ Key exchange response sent successfully');

      // Remove from pending requests
      setPendingRequests((prev) => prev.filter((r) => r.sessionId !== request.sessionId));

      // Clear message after delay
      setTimeout(() => {
        setSuccessMessage('');
      }, 5000);
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
