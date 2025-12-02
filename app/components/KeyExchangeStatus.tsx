'use client';

import { useState, useEffect } from 'react';
import type { KeyExchangeStatus as StatusType } from '@/types';

interface Props {
  sessionId: string;
  peerUsername: string;
}

/**
 * Key Exchange Status Component
 *
 * Displays real-time status of a key exchange session
 * Polls the server for status updates
 */
export default function KeyExchangeStatus({ sessionId, peerUsername }: Props) {
  const [status, setStatus] = useState<StatusType>('initiated');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const response = await fetch(`/api/key-exchange/status/${sessionId}`);
        const data = await response.json();

        if (data.success) {
          setStatus(data.status);
          setLoading(false);

          // Stop polling once confirmed or failed
          if (data.status === 'confirmed' || data.status === 'failed') {
            return true; // Signal to stop polling
          }
        }
      } catch (err) {
        console.error('Failed to fetch status:', err);
        setError('Failed to fetch status');
      }
      return false;
    };

    // Initial fetch
    fetchStatus();

    // Poll every 3 seconds
    const interval = setInterval(async () => {
      const shouldStop = await fetchStatus();
      if (shouldStop) {
        clearInterval(interval);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, [sessionId]);

  const getStatusDisplay = () => {
    switch (status) {
      case 'initiated':
        return {
          text: 'Waiting for response...',
          color: '#ffc107',
          icon: '⏳',
        };
      case 'responded':
        return {
          text: 'Waiting for confirmation...',
          color: '#17a2b8',
          icon: '⏳',
        };
      case 'confirmed':
        return {
          text: 'Key exchange complete!',
          color: '#28a745',
          icon: '✅',
        };
      case 'failed':
        return {
          text: 'Key exchange failed',
          color: '#dc3545',
          icon: '❌',
        };
      default:
        return {
          text: 'Unknown status',
          color: '#6c757d',
          icon: '❓',
        };
    }
  };

  if (loading) {
    return (
      <div style={{ padding: '0.5rem', color: '#666' }}>
        Loading status...
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ padding: '0.5rem', color: '#dc3545' }}>
        {error}
      </div>
    );
  }

  const statusDisplay = getStatusDisplay();

  return (
    <div
      style={{
        padding: '0.75rem',
        backgroundColor: '#f8f9fa',
        borderLeft: `4px solid ${statusDisplay.color}`,
        borderRadius: '4px',
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
      }}
    >
      <span style={{ fontSize: '1.2rem' }}>{statusDisplay.icon}</span>
      <div>
        <div style={{ fontWeight: 'bold', color: statusDisplay.color }}>
          {statusDisplay.text}
        </div>
        <div style={{ fontSize: '0.9rem', color: '#666' }}>
          Key exchange with {peerUsername}
        </div>
      </div>
    </div>
  );
}
