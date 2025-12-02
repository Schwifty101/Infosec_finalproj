/**
 * FileAttachment Component
 *
 * Displays encrypted file attachments with download functionality
 * Handles client-side decryption before triggering browser download
 */

'use client';

import { useState } from 'react';
import { getSessionKey } from '@/lib/crypto/sessionKeys';
import { decryptFile } from '@/lib/crypto/fileEncryption';

interface FileAttachmentProps {
  fileId: string;
  filename: string;
  mimeType: string;
  size: number;
  uploadedAt: Date;
  senderId: string;
  currentUserId: string;
  conversationId: string;
}

export default function FileAttachment({
  fileId,
  filename,
  mimeType,
  size,
  uploadedAt,
  senderId,
  currentUserId,
  conversationId,
}: FileAttachmentProps) {
  const [downloadStatus, setDownloadStatus] = useState<
    'idle' | 'downloading' | 'decrypting' | 'complete' | 'error'
  >('idle');
  const [errorMessage, setErrorMessage] = useState('');

  const handleDownload = async () => {
    setDownloadStatus('downloading');
    setErrorMessage('');

    try {
      // 1. Fetch encrypted file from server
      const response = await fetch(`/api/files/download/${fileId}`, {
        headers: {
          'X-User-Id': currentUserId,
        },
      });

      const data = await response.json();

      if (!data.success) {
        throw new Error(data.message || 'Failed to download file');
      }

      const file = data.file;
      setDownloadStatus('decrypting');

      // 2. Get session key from IndexedDB
      const sessionKey = await getSessionKey(conversationId);
      if (!sessionKey) {
        throw new Error(
          'Session key not found. Please exchange keys with this user first.'
        );
      }

      // 3. Decrypt file using AES-256-GCM
      const decryptedData = await decryptFile(
        file.ciphertext,
        file.iv,
        file.authTag,
        file.nonce,
        file.filename,
        file.mimeType,
        sessionKey
      );

      // 4. Create Blob and trigger browser download
      const blob = new Blob([decryptedData], { type: file.mimeType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      setDownloadStatus('complete');

      // Reset to idle after 2 seconds
      setTimeout(() => {
        setDownloadStatus('idle');
      }, 2000);
    } catch (error: any) {
      console.error('❌ Download/decryption failed:', error);
      setErrorMessage(error.message);
      setDownloadStatus('error');

      // Log decryption failure for security audit
      try {
        await fetch('/api/security/log', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            type: 'decrypt_fail',
            userId: currentUserId,
            details: `File decryption failed: ${fileId}`,
            fileId,
          }),
        });
      } catch (logError) {
        console.error('Failed to log decryption failure:', logError);
      }
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  const getFileIcon = (mimeType: string): string => {
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType === 'application/pdf') return '📄';
    if (mimeType.includes('word')) return '📝';
    if (mimeType.includes('sheet') || mimeType.includes('excel')) return '📊';
    if (mimeType.startsWith('video/')) return '🎥';
    if (mimeType.startsWith('audio/')) return '🎵';
    if (mimeType.includes('zip') || mimeType.includes('compressed'))
      return '📦';
    return '📎';
  };

  const isSentByMe = senderId === currentUserId;

  return (
    <div
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '0.75rem',
        padding: '0.75rem 1rem',
        backgroundColor: isSentByMe ? '#d1e7ff' : '#e9ecef',
        borderRadius: '12px',
        maxWidth: '320px',
        border: '1px solid rgba(0,0,0,0.1)',
        marginBottom: '0.5rem',
      }}
    >
      {/* File icon */}
      <div style={{ fontSize: '2rem', flexShrink: 0 }}>
        {getFileIcon(mimeType)}
      </div>

      {/* File info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div
          style={{
            fontWeight: 'bold',
            fontSize: '0.9rem',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            color: '#212529',
          }}
        >
          {filename}
        </div>
        <div
          style={{
            fontSize: '0.75rem',
            color: '#6c757d',
            marginTop: '0.25rem',
          }}
        >
          {formatFileSize(size)}
        </div>
        {errorMessage && (
          <div
            style={{
              fontSize: '0.75rem',
              color: '#dc3545',
              marginTop: '0.25rem',
            }}
          >
            {errorMessage}
          </div>
        )}
      </div>

      {/* Download button */}
      <button
        onClick={handleDownload}
        disabled={
          downloadStatus === 'downloading' || downloadStatus === 'decrypting'
        }
        style={{
          padding: '0.5rem 0.75rem',
          backgroundColor:
            downloadStatus === 'complete'
              ? '#28a745'
              : downloadStatus === 'error'
              ? '#dc3545'
              : '#007bff',
          color: 'white',
          border: 'none',
          borderRadius: '8px',
          fontSize: '0.85rem',
          cursor:
            downloadStatus === 'downloading' || downloadStatus === 'decrypting'
              ? 'not-allowed'
              : 'pointer',
          whiteSpace: 'nowrap',
          flexShrink: 0,
          opacity:
            downloadStatus === 'downloading' || downloadStatus === 'decrypting'
              ? 0.7
              : 1,
        }}
      >
        {downloadStatus === 'idle' && '⬇️ Download'}
        {downloadStatus === 'downloading' && '⏳ Downloading...'}
        {downloadStatus === 'decrypting' && '🔓 Decrypting...'}
        {downloadStatus === 'complete' && '✅ Complete'}
        {downloadStatus === 'error' && '❌ Error'}
      </button>
    </div>
  );
}
