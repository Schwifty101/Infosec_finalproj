/**
 * Custom Node.js Server with Socket.io Integration
 *
 * Integrates Socket.io WebSocket server with Next.js for real-time messaging
 * Handles message routing, typing indicators, online/offline status
 */

const { createServer } = require('http');
const { parse } = require('url');
const next = require('next');
const { Server } = require('socket.io');

const dev = process.env.NODE_ENV !== 'production';
const hostname = 'localhost';
const port = parseInt(process.env.PORT, 10) || 3000;

// Initialize Next.js app
const app = next({ dev, hostname, port });
const handle = app.getRequestHandler();

console.log('🚀 Starting custom server with Socket.io...');

app.prepare().then(() => {
  // Create HTTP server
  const httpServer = createServer(async (req, res) => {
    try {
      const parsedUrl = parse(req.url, true);
      await handle(req, res, parsedUrl);
    } catch (err) {
      console.error('Error occurred handling', req.url, err);
      res.statusCode = 500;
      res.end('internal server error');
    }
  });

  // Initialize Socket.io
  const io = new Server(httpServer, {
    cors: {
      origin: process.env.NEXT_PUBLIC_APP_URL || `http://${hostname}:${port}`,
      methods: ['GET', 'POST'],
      credentials: true,
    },
    // Connection settings
    pingTimeout: 60000,
    pingInterval: 25000,
  });

  // Map userId to socket.id for message routing
  const userSockets = new Map(); // userId -> socketId

  // Track online users
  const onlineUsers = new Set();

  console.log('✅ Socket.io initialized');

  // WebSocket connection handler
  io.on('connection', (socket) => {
    console.log(`🔌 Client connected: ${socket.id}`);

    // Authenticate socket connection
    socket.on('auth:register', (userId) => {
      if (!userId) {
        console.warn('⚠️ Socket connection without userId, disconnecting');
        socket.disconnect();
        return;
      }

      // Map userId to socket
      userSockets.set(userId, socket.id);
      onlineUsers.add(userId);
      socket.userId = userId; // Attach userId to socket

      console.log(`✅ User ${userId} registered with socket ${socket.id}`);

      // Notify user of successful authentication
      socket.emit('auth:success', {
        userId,
        timestamp: Date.now(),
      });

      // Notify others that this user is online
      socket.broadcast.emit('user:online', { userId });

      // Send pending messages if any
      socket.emit('pending:check', {
        message: 'Check for pending messages',
      });
    });

    // Handle message send
    socket.on('message:send', async (data) => {
      const { receiverId, message } = data;

      if (!socket.userId) {
        console.warn('⚠️ Unauthenticated socket trying to send message');
        socket.emit('error', { message: 'Not authenticated' });
        return;
      }

      console.log(`📤 Message from ${socket.userId} to ${receiverId}`);

      // Find recipient socket
      const recipientSocketId = userSockets.get(receiverId);

      if (recipientSocketId) {
        // Recipient is online, forward message immediately
        io.to(recipientSocketId).emit('message:receive', {
          ...message,
          receivedAt: Date.now(),
        });

        console.log(`✅ Message delivered to ${receiverId} (online)`);

        // Send delivery confirmation to sender
        socket.emit('message:delivered', {
          messageId: message._id,
          deliveredAt: Date.now(),
        });
      } else {
        // Recipient offline, message stored in DB by API route
        console.log(`📦 Message stored for ${receiverId} (offline)`);

        socket.emit('message:stored', {
          messageId: message._id,
          status: 'offline',
        });
      }
    });

    // Handle typing indicators
    socket.on('typing:start', ({ receiverId }) => {
      if (!socket.userId) return;

      const recipientSocketId = userSockets.get(receiverId);

      if (recipientSocketId) {
        io.to(recipientSocketId).emit('typing:indicator', {
          senderId: socket.userId,
          typing: true,
        });
      }
    });

    socket.on('typing:stop', ({ receiverId }) => {
      if (!socket.userId) return;

      const recipientSocketId = userSockets.get(receiverId);

      if (recipientSocketId) {
        io.to(recipientSocketId).emit('typing:indicator', {
          senderId: socket.userId,
          typing: false,
        });
      }
    });

    // Handle read receipts
    socket.on('message:read', ({ messageId, senderId }) => {
      if (!socket.userId) return;

      const senderSocketId = userSockets.get(senderId);

      if (senderSocketId) {
        io.to(senderSocketId).emit('message:read', {
          messageId,
          readBy: socket.userId,
          readAt: Date.now(),
        });
      }
    });

    // Handle online status requests
    socket.on('status:check', ({ userId }) => {
      const isOnline = onlineUsers.has(userId);
      socket.emit('status:response', {
        userId,
        online: isOnline,
      });
    });

    // Handle disconnect
    socket.on('disconnect', (reason) => {
      console.log(`🔌 Client disconnected: ${socket.id} (${reason})`);

      if (socket.userId) {
        // Remove from maps
        userSockets.delete(socket.userId);
        onlineUsers.delete(socket.userId);

        // Notify others that this user is offline
        socket.broadcast.emit('user:offline', {
          userId: socket.userId,
        });

        console.log(`👋 User ${socket.userId} went offline`);
      }
    });

    // Handle errors
    socket.on('error', (error) => {
      console.error(`❌ Socket error for ${socket.id}:`, error);
    });
  });

  // Start HTTP server
  httpServer
    .once('error', (err) => {
      console.error('❌ Server error:', err);
      process.exit(1);
    })
    .listen(port, () => {
      console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║  ✅ Server running on http://${hostname}:${port}              ║
║  🔌 Socket.io WebSocket server ready                      ║
║  🔐 Secure E2E Encrypted Messaging - Phase 3              ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
      `);
    });

  // Graceful shutdown
  const gracefulShutdown = () => {
    console.log('\n🛑 Shutting down gracefully...');

    // Close all socket connections
    io.close(() => {
      console.log('✅ Socket.io connections closed');
    });

    // Close HTTP server
    httpServer.close(() => {
      console.log('✅ HTTP server closed');
      process.exit(0);
    });

    // Force close after 10 seconds
    setTimeout(() => {
      console.error('❌ Forced shutdown after timeout');
      process.exit(1);
    }, 10000);
  };

  process.on('SIGTERM', gracefulShutdown);
  process.on('SIGINT', gracefulShutdown);
});
