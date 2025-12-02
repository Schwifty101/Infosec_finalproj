'use client';

import { useState, useEffect } from 'react';

interface SecurityLog {
  _id: string;
  type: string;
  userId?: string;
  details: string;
  timestamp: string;
  success?: boolean;
  ipAddress?: string;
}

export default function LogsPage() {
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [typeFilter, setTypeFilter] = useState('');
  const [total, setTotal] = useState(0);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (typeFilter) params.append('type', typeFilter);
      params.append('limit', '50');

      const response = await fetch(`/api/logs?${params.toString()}`);
      const data = await response.json();

      if (data.success) {
        setLogs(data.logs);
        setTotal(data.total);
      }
    } catch (error) {
      console.error('Failed to fetch logs:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [typeFilter]);

  const exportCSV = () => {
    const headers = ['Timestamp', 'Type', 'User ID', 'Details', 'Success', 'IP Address'];
    const rows = logs.map(log => [
      new Date(log.timestamp).toISOString(),
      log.type,
      log.userId || '',
      log.details,
      log.success !== undefined ? log.success.toString() : '',
      log.ipAddress || '',
    ]);

    const csvContent = [
      headers.join(','),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-logs-${new Date().toISOString()}.csv`;
    a.click();
  };

  return (
    <div style={{ padding: '2rem', maxWidth: '1200px', margin: '0 auto' }}>
      <h1>Security Logs</h1>

      <div style={{ marginBottom: '1rem', display: 'flex', gap: '1rem' }}>
        <select
          value={typeFilter}
          onChange={(e) => setTypeFilter(e.target.value)}
          style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid #ccc' }}
        >
          <option value="">All Types</option>
          <option value="auth">Authentication</option>
          <option value="key_exchange">Key Exchange</option>
          <option value="replay_detected">Replay Detected</option>
          <option value="invalid_sequence">Invalid Sequence</option>
          <option value="decrypt_fail">Decryption Failure</option>
          <option value="message_access">Message Access</option>
          <option value="expired_timestamp">Expired Timestamp</option>
        </select>

        <button
          onClick={exportCSV}
          style={{
            padding: '0.5rem 1rem',
            backgroundColor: '#007bff',
            color: 'white',
            border: 'none',
            borderRadius: '4px',
            cursor: 'pointer',
          }}
        >
          Export CSV
        </button>

        <span style={{ marginLeft: 'auto', padding: '0.5rem' }}>
          Total: {total} logs
        </span>
      </div>

      {loading ? (
        <p>Loading logs...</p>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ backgroundColor: '#f8f9fa', borderBottom: '2px solid #dee2e6' }}>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Timestamp</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Type</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>User ID</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Details</th>
              <th style={{ padding: '0.75rem', textAlign: 'left' }}>Success</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr
                key={log._id}
                style={{
                  borderBottom: '1px solid #dee2e6',
                  backgroundColor: log.success === false ? '#fff3cd' : 'white',
                }}
              >
                <td style={{ padding: '0.75rem', fontSize: '0.875rem' }}>
                  {new Date(log.timestamp).toLocaleString()}
                </td>
                <td style={{ padding: '0.75rem' }}>
                  <code>{log.type}</code>
                </td>
                <td style={{ padding: '0.75rem', fontSize: '0.875rem' }}>
                  {log.userId ? log.userId.substring(0, 8) + '...' : '-'}
                </td>
                <td style={{ padding: '0.75rem', fontSize: '0.875rem' }}>{log.details}</td>
                <td style={{ padding: '0.75rem' }}>
                  {log.success !== undefined ? (
                    <span
                      style={{
                        color: log.success ? 'green' : 'red',
                        fontWeight: 'bold',
                      }}
                    >
                      {log.success ? '✓' : '✗'}
                    </span>
                  ) : (
                    '-'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
