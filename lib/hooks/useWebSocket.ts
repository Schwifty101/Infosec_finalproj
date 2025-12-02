/**
 * WebSocket Hook for Real-time Messaging
 *
 * React hook that manages Socket.io WebSocket connection
 * Provides connection state and socket instance for messaging
 */

'use client';

import { useEffect, useState, useRef } from 'react';
import { io, Socket } from 'socket.io-client';

export interface UseWebSocketReturn {
  socket: Socket | null;
  connected: boolean;
  error: string | null;
}

/**
 * Custom hook for managing WebSocket connection
 *
 * @param userId - User ID for authentication (from sessionStorage)
 * @returns Socket instance, connection state, and error state
 */
export function useWebSocket(userId: string | null): UseWebSocketReturn {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);

  useEffect(() => {
    // Don't connect if no userId
    if (!userId) {
      console.log('⚠️ WebSocket: No userId, skipping connection');
      return;
    }

    // Don't reconnect if already connected
    if (socketRef.current?.connected) {
      console.log('✅ WebSocket: Already connected');
      return;
    }

    console.log('🔌 WebSocket: Connecting...');

    // Initialize Socket.io connection
    const socketInstance = io(
      process.env.NEXT_PUBLIC_WS_URL || 'http://localhost:3000',
      {
        transports: ['websocket', 'polling'], // Prefer WebSocket, fallback to polling
        reconnection: true,
        reconnectionAttempts: 5,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        timeout: 20000,
      }
    );

    // Handle connection success
    socketInstance.on('connect', () => {
      console.log('✅ WebSocket: Connected', socketInstance.id);
      setConnected(true);
      setError(null);

      // Authenticate with userId
      socketInstance.emit('auth:register', userId);
    });

    // Handle authentication success
    socketInstance.on('auth:success', (data) => {
      console.log('✅ WebSocket: Authenticated', data);
    });

    // Handle disconnection
    socketInstance.on('disconnect', (reason) => {
      console.log('🔌 WebSocket: Disconnected', reason);
      setConnected(false);

      if (reason === 'io server disconnect') {
        // Server disconnected, try to reconnect manually
        socketInstance.connect();
      }
    });

    // Handle connection errors
    socketInstance.on('connect_error', (err) => {
      console.error('❌ WebSocket: Connection error', err.message);
      setError(`Connection failed: ${err.message}`);
      setConnected(false);
    });

    // Handle reconnection attempts
    socketInstance.on('reconnect_attempt', (attemptNumber) => {
      console.log(`🔄 WebSocket: Reconnection attempt ${attemptNumber}`);
    });

    // Handle successful reconnection
    socketInstance.on('reconnect', (attemptNumber) => {
      console.log(`✅ WebSocket: Reconnected after ${attemptNumber} attempts`);
      setConnected(true);
      setError(null);

      // Re-authenticate after reconnection
      socketInstance.emit('auth:register', userId);
    });

    // Handle reconnection failure
    socketInstance.on('reconnect_failed', () => {
      console.error('❌ WebSocket: Reconnection failed after maximum attempts');
      setError('Failed to reconnect to server');
      setConnected(false);
    });

    // Handle general errors
    socketInstance.on('error', (err) => {
      console.error('❌ WebSocket: Error', err);
      setError(`WebSocket error: ${err}`);
    });

    // Store in state and ref
    setSocket(socketInstance);
    socketRef.current = socketInstance;

    // Cleanup on unmount
    return () => {
      console.log('🛑 WebSocket: Disconnecting...');
      if (socketRef.current) {
        socketRef.current.disconnect();
        socketRef.current = null;
      }
    };
  }, [userId]);

  return {
    socket,
    connected,
    error,
  };
}

/**
 * Helper function to check if user is online
 *
 * @param socket - Socket.io instance
 * @param userId - User ID to check
 * @returns Promise<boolean> - True if user is online
 */
export function checkUserOnlineStatus(
  socket: Socket | null,
  userId: string
): Promise<boolean> {
  return new Promise((resolve) => {
    if (!socket || !socket.connected) {
      resolve(false);
      return;
    }

    // Set timeout for response
    const timeout = setTimeout(() => {
      socket.off('status:response');
      resolve(false);
    }, 5000);

    // Listen for response
    socket.once('status:response', (data: { userId: string; online: boolean }) => {
      clearTimeout(timeout);
      if (data.userId === userId) {
        resolve(data.online);
      } else {
        resolve(false);
      }
    });

    // Request status
    socket.emit('status:check', { userId });
  });
}
